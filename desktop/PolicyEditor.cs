using System.Text.Json;

namespace Forten.Desktop;

internal sealed class PolicyEditor : Form
{
    private static readonly string[] Types =
        ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "DST-PORT", "NETWORK"];

    private readonly TextBox path = new() { Dock = DockStyle.Fill };
    private readonly ComboBox node = new() { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly DataGridView table = new()
    {
        Dock = DockStyle.Fill, BackgroundColor = Color.White, RowHeadersVisible = false, MultiSelect = false,
        AllowUserToAddRows = false, AllowUserToDeleteRows = false, AllowUserToResizeRows = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        EditMode = DataGridViewEditMode.EditOnEnter
    };

    public string Executable => path.Text.Trim();
    public string Node => node.SelectedItem as string ?? "";
    public string Rules { get; private set; } = "[]";

    public PolicyEditor(string[] nodes, string? defaultNode, JsonElement? policy)
    {
        Text = policy.HasValue ? "编辑应用策略" : "添加应用策略";
        Font = new Font("Microsoft YaHei UI", 10);
        StartPosition = FormStartPosition.CenterParent;
        MinimumSize = new Size(690, 440);
        Size = new Size(760, 510);
        AutoScaleMode = AutoScaleMode.Font;
        node.Items.AddRange(nodes);
        node.Items.Add("REJECT");
        node.SelectedItem = policy?.GetProperty("node").GetString() ?? defaultNode ?? nodes[0];

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 3, RowCount = 6 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 97));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        Controls.Add(layout);
        layout.Controls.Add(Caption("程序路径"), 0, 0);
        layout.Controls.Add(path, 1, 0);
        var browse = Dashboard.ButtonFor("浏览…");
        browse.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog { Filter = "Windows 程序 (*.exe)|*.exe" };
            if (dialog.ShowDialog(this) == DialogResult.OK) path.Text = dialog.FileName;
        };
        layout.Controls.Add(browse, 2, 0);
        if (policy.HasValue)
        {
            path.Text = policy.Value.GetProperty("exe").GetString();
            path.ReadOnly = true;
            browse.Enabled = false;
        }
        layout.Controls.Add(Caption("默认出口"), 0, 1);
        layout.Controls.Add(node, 1, 1);

        var controls = Dashboard.Bar();
        Add(controls, "添加规则", () => table.Rows.Add(Types[1], "", node.SelectedItem));
        Add(controls, "移除", () => { if (table.CurrentRow is { } row) table.Rows.Remove(row); });
        Add(controls, "上移", () => MoveRule(-1));
        Add(controls, "下移", () => MoveRule(1));
        layout.Controls.Add(controls, 0, 2);
        layout.SetColumnSpan(controls, 3);
        table.Columns.Add(new DataGridViewComboBoxColumn { HeaderText = "匹配类型", DataSource = Types, FillWeight = 85 });
        table.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "匹配值", FillWeight = 125 });
        table.Columns.Add(new DataGridViewComboBoxColumn { HeaderText = "出口", DataSource = nodes.Append("REJECT").ToArray() });
        foreach (DataGridViewColumn column in table.Columns) column.SortMode = DataGridViewColumnSortMode.NotSortable;
        layout.Controls.Add(table, 0, 3);
        layout.SetColumnSpan(table, 3);
        if (policy?.GetProperty("rules") is { ValueKind: JsonValueKind.Array } rules)
        {
            foreach (var rule in rules.EnumerateArray())
                table.Rows.Add(rule.GetProperty("type").GetString(), rule.GetProperty("value").GetString(), rule.GetProperty("node").GetString());
        }

        var hint = Caption("按从上到下的顺序匹配；没有命中时使用默认出口。REJECT 表示阻断。");
        hint.ForeColor = Color.DimGray;
        layout.Controls.Add(hint, 0, 4);
        layout.SetColumnSpan(hint, 3);

        var footer = Dashboard.Bar();
        footer.FlowDirection = FlowDirection.RightToLeft;
        var save = Dashboard.ButtonFor("保存策略", true);
        save.Click += (_, _) => Save();
        var cancel = Dashboard.ButtonFor("取消");
        cancel.DialogResult = DialogResult.Cancel;
        footer.Controls.AddRange([save, cancel]);
        AcceptButton = save;
        CancelButton = cancel;
        layout.Controls.Add(footer, 0, 5);
        layout.SetColumnSpan(footer, 3);
    }

    private static Label Caption(string text) => new()
    {
        Text = text, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft
    };

    private static void Add(FlowLayoutPanel target, string caption, Action action)
    {
        var button = Dashboard.ButtonFor(caption);
        button.Click += (_, _) => { action(); };
        target.Controls.Add(button);
    }

    private void MoveRule(int step)
    {
        table.EndEdit();
        if (table.CurrentRow is not { } row) return;
        int index = row.Index + step;
        if (index < 0 || index >= table.Rows.Count) return;
        var values = row.Cells.Cast<DataGridViewCell>().Select(cell => cell.Value).ToArray();
        table.Rows.Remove(row);
        table.Rows.Insert(index, values);
        table.CurrentCell = table.Rows[index].Cells[0];
    }

    private void Save()
    {
        table.EndEdit();
        if (Executable.Length == 0 || Node.Length == 0 ||
            table.Rows.Cast<DataGridViewRow>().Any(row => row.Cells.Cast<DataGridViewCell>().Any(cell => string.IsNullOrWhiteSpace(cell.Value?.ToString()))))
        {
            MessageBox.Show(this, "请填写应用路径、默认出口和全部分流规则。", "应用策略", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        Rules = JsonSerializer.Serialize(table.Rows.Cast<DataGridViewRow>().Select(row => new
        {
            type = row.Cells[0].Value?.ToString(),
            value = row.Cells[1].Value?.ToString(),
            node = row.Cells[2].Value?.ToString()
        }));
        DialogResult = DialogResult.OK;
    }
}
