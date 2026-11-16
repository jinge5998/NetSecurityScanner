using Avalonia;
using Avalonia.Controls;
using Avalonia.Diagnostics;

namespace NetSecurityScanner.Views;

public partial class NetworkTopologyWindow : Window
{
    public NetworkTopologyWindow()
    {
        InitializeComponent();
        
#if DEBUG
        this.AttachDevTools();
#endif
    }
}