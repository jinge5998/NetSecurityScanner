using Avalonia;
using Avalonia.Controls;
using Avalonia.Diagnostics;

namespace NetSecurityScanner.Views;

public partial class AssetManagementWindow : Window
{
    public AssetManagementWindow()
    {
        InitializeComponent();
        
#if DEBUG
        this.AttachDevTools();
#endif
    }
}