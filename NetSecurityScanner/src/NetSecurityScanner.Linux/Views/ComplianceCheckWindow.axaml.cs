using Avalonia;
using Avalonia.Controls;
using Avalonia.Diagnostics;

namespace NetSecurityScanner.Views;

public partial class ComplianceCheckWindow : Window
{
    public ComplianceCheckWindow()
    {
        InitializeComponent();
        
#if DEBUG
        this.AttachDevTools();
#endif
    }
}