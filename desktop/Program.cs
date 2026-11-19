using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Forten.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new Dashboard());
    }
}

internal static class Cli
{
    public static async Task<JsonElement> Run(string? input, params string[] arguments)
    {
        var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "forten.exe"))
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input != null,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        if (input != null)
            info.StandardInputEncoding = new UTF8Encoding(false);
        foreach (var argument in arguments)
            info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("无法启动 forten.exe");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (input != null)
        {
            await process.StandardInput.WriteAsync(input);
            process.StandardInput.Close();
        }
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
        {
            var error = await stderr;
            try { error = JsonDocument.Parse(error).RootElement.GetProperty("error").GetString() ?? error; }
            catch (JsonException) { }
            throw new InvalidOperationException(error.Length == 0 ? $"Forten 错误 {process.ExitCode}" : error);
        }
        using var doc = JsonDocument.Parse(await stdout);
        return doc.RootElement.Clone();
    }
}

internal sealed class Dashboard : Form
{
    private readonly Label status = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly TextBox source = new() { Width = 360, UseSystemPasswordChar = true, PlaceholderText = "Clash HTTPS 订阅地址" };
    private readonly ComboBox selected = new() { Width = 330, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly DataGridView applications = Grid();
    private readonly DataGridView connections = Grid();
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 4000 };
    private readonly List<JsonElement> policies = [];
    private readonly List<Control> actionControls = [];
    private string[] nodes = [];
    private bool busy;

    public Dashboard()
    {
        Text = "Forten";
        Font = new Font("Microsoft YaHei UI", 10);
        MinimumSize = new Size(900, 610);
        Size = new Size(1060, 710);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(245, 248, 250);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24, 10, 24, 16), ColumnCount = 1, RowCount = 6 };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 65));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        Controls.Add(layout);

        var heading = new Label
        {
            Text = "Forten", Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 30, FontStyle.Bold), ForeColor = Color.FromArgb(15, 36, 53)
        };
        layout.Controls.Add(heading, 0, 0);
        var lifecycle = Bar();
        lifecycle.Controls.AddRange([
            ActionButton("启动 / 应用", async () => { await Cli.Run(null, "start"); await Reload(); }, true),
            ActionButton("停止并保持阻断", async () => { await Cli.Run(null, "stop"); await Reload(); }),
            ActionButton("停止并解除阻断", Release),
            ActionButton("以管理员身份打开", Elevate)
        ]);
        layout.Controls.Add(lifecycle, 0, 1);

        var subscription = Bar();
        subscription.Controls.AddRange([
            source,
            ActionButton("导入订阅", async () =>
            {
                await Cli.Run(source.Text, "subscription", "import", "--stdin");
                source.Clear();
                await Reload();
            }),
            ActionButton("导入 YAML", ImportFile),
            ActionButton("刷新订阅", async () => { await Cli.Run(null, "subscription", "refresh"); await Reload(); })
        ]);
        layout.Controls.Add(subscription, 0, 2);
        var selection = Bar();
        selection.Controls.AddRange([
            new Label { Text = "默认节点", AutoSize = true, Margin = new Padding(3, 9, 9, 0) },
            selected,
            ActionButton("保存默认节点", async () =>
            {
                if (selected.SelectedItem is string node)
                    await Cli.Run(null, "node", "select", "--name", node);
                await Reload();
            }),
            new Label { AutoSize = true, Text = "有应用策略时，未匹配的流量会被拒绝", ForeColor = Color.DimGray, Margin = new Padding(16, 9, 0, 0) }
        ]);
        layout.Controls.Add(selection, 0, 3);

        applications.Columns.Add("exe", "应用程序路径");
        applications.Columns.Add("node", "默认出口");
        applications.Columns.Add("rules", "分流规则");
        applications.Columns[0].FillWeight = 220;
        applications.Columns[2].FillWeight = 60;
        connections.Columns.Add("exe", "进程");
        connections.Columns.Add("host", "目的地址");
        connections.Columns.Add("node", "节点");
        connections.Columns.Add("rule", "匹配规则");
        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(Page("应用策略", applications,
            ActionButton("添加应用", () => Edit(false), true),
            ActionButton("编辑策略", () => Edit(true)),
            ActionButton("移除策略", Remove)));
        tabs.TabPages.Add(Page("活动连接", connections, ActionButton("刷新连接", LoadConnections)));
        layout.Controls.Add(tabs, 0, 4);
        layout.Controls.Add(status, 0, 5);
        Shown += async (_, _) =>
        {
            await Execute(Reload);
            timer.Start();
        };
        timer.Tick += async (_, _) =>
        {
            if (!busy)
            {
                try { await LoadStatus(); }
                catch { /* Keep the latest status during another CLI operation. */ }
            }
        };
        FormClosed += (_, _) => timer.Dispose();
    }

    private static TabPage Page(string title, Control grid, params Control[] actions)
    {
        var page = new TabPage(title) { Padding = new Padding(8) };
        var bar = Bar();
        bar.Dock = DockStyle.Top;
        bar.Height = 42;
        bar.Controls.AddRange(actions);
        page.Controls.Add(grid);
        page.Controls.Add(bar);
        return page;
    }

    private static DataGridView Grid() => new()
    {
        Dock = DockStyle.Fill, BackgroundColor = Color.White, BorderStyle = BorderStyle.FixedSingle,
        ReadOnly = true, RowHeadersVisible = false, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
        AllowUserToResizeRows = false, MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
    };

    internal static FlowLayoutPanel Bar() => new() { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 2, 0, 0) };

    internal static Button ButtonFor(string title, bool primary = false)
    {
        var button = new Button { Text = title, AutoSize = true, Height = 31, Padding = new Padding(7, 0, 7, 0) };
        if (primary)
        {
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 0;
            button.BackColor = Color.FromArgb(0, 111, 122);
            button.ForeColor = Color.White;
        }
        return button;
    }

    private Button ActionButton(string title, Func<Task> action, bool primary = false)
    {
        var button = ButtonFor(title, primary);
        button.Click += async (_, _) => await Execute(action);
        actionControls.Add(button);
        return button;
    }

    private async Task Execute(Func<Task> action)
    {
        if (busy) return;
        busy = true;
        foreach (var control in actionControls) control.Enabled = false;
        UseWaitCursor = true;
        try { await action(); }
        catch (Exception err)
        {
            MessageBox.Show(this, err.Message, "Forten", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            try { await LoadStatus(); }
            catch { /* The original error is already visible. */ }
        }
        finally
        {
            UseWaitCursor = false;
            foreach (var control in actionControls) control.Enabled = true;
            busy = false;
        }
    }

    private async Task Reload()
    {
        var snapshot = await Cli.Run(null, "nodes");
        nodes = snapshot.GetProperty("nodes").EnumerateArray().Select(value => value.GetString()!).ToArray();
        selected.Items.Clear();
        selected.Items.AddRange(nodes);
        selected.SelectedItem = snapshot.GetProperty("selected").GetString();
        var items = await Cli.Run(null, "policies");
        policies.Clear();
        applications.Rows.Clear();
        foreach (var policy in items.GetProperty("policies").EnumerateArray())
        {
            var count = policy.GetProperty("rules");
            var index = applications.Rows.Add(policy.GetProperty("exe").GetString(), policy.GetProperty("node").GetString(),
                count.ValueKind == JsonValueKind.Array ? count.GetArrayLength() : 0);
            applications.Rows[index].Tag = policies.Count;
            policies.Add(policy);
        }
        await LoadStatus();
    }

    private async Task LoadStatus()
    {
        var result = await Cli.Run(null, "status");
        var state = result.GetProperty("state").GetString() switch
        {
            "running" => "TUN 运行中", "starting" => "正在启动", "degraded" => "保护状态异常",
            "offline" => "TUN 已离线", "failed" => "运行失败", _ => "TUN 已停止"
        };
        var guard = result.GetProperty("guard").GetString() switch
        {
            "installed" => "应用阻断已安装", "incomplete" => "应用阻断不完整", "unknown" => "无法读取应用阻断状态", _ => "无应用阻断"
        };
        var pending = result.GetProperty("pending").GetBoolean() ? "  ·  有待应用的更改" : "";
        var admin = result.GetProperty("elevated").GetBoolean() ? "" : "  ·  启停需要管理员权限";
        status.Text = state + "  ·  " + guard + pending + admin;
    }

    private async Task LoadConnections()
    {
        var result = await Cli.Run(null, "connections");
        connections.Rows.Clear();
        foreach (var row in result.GetProperty("connections").EnumerateArray())
        {
            var host = row.GetProperty("host").ToString();
            if (host.Length == 0) host = row.GetProperty("destination_ip").ToString();
            connections.Rows.Add(row.GetProperty("process").ToString(),
                host + ":" + row.GetProperty("destination_port").ToString(),
                string.Join(" → ", row.GetProperty("nodes").EnumerateArray().Select(node => node.ToString())),
                row.GetProperty("rule").ToString());
        }
    }

    private JsonElement? SelectedPolicy() => applications.CurrentRow?.Tag is int index ? policies[index] : null;

    private async Task Edit(bool existing)
    {
        if (nodes.Length == 0) throw new InvalidOperationException("请先导入订阅或 YAML 文件。");
        var policy = existing ? SelectedPolicy() : null;
        if (existing && policy == null) return;
        using var editor = new PolicyEditor(nodes, selected.SelectedItem as string, policy);
        if (editor.ShowDialog(this) != DialogResult.OK) return;
        await Cli.Run(editor.Rules, "policy", "set", "--exe", editor.Executable, "--node", editor.Node, "--rules", "-");
        await Reload();
    }

    private async Task Remove()
    {
        var path = SelectedPolicy()?.GetProperty("exe").GetString();
        if (path == null) return;
        if (MessageBox.Show(this, "移除配置后，已安装的 Windows 阻断会继续保留。", "移除应用策略",
                MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
        await Cli.Run(null, "policy", "remove", "--exe", path);
        await Reload();
    }

    private async Task ImportFile()
    {
        using var dialog = new OpenFileDialog { Filter = "Clash YAML (*.yaml;*.yml)|*.yaml;*.yml|所有文件 (*.*)|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        await Cli.Run(null, "subscription", "import", "--file", dialog.FileName);
        await Reload();
    }

    private async Task Release()
    {
        if (MessageBox.Show(this, "解除后，应用可能直接使用当前网络。", "停止并解除阻断",
                MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return;
        await Cli.Run(null, "release");
        await Reload();
    }

    private Task Elevate()
    {
        Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
        return Task.CompletedTask;
    }
}
