using Avalonia;
using Avalonia.Controls;
using Avalonia.Diagnostics;

namespace NetSecurityScanner.Views;

public partial class AttackLogWindow : Window
{
    public AttackLogWindow()
    {
        InitializeComponent();
        
#if DEBUG
        this.AttachDevTools();
#endif
    }
}