using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Collections;
using System.Resources;
using System.Xaml;
using System.Windows;
using System.Windows.Markup;
using System.Xml;

class Program {
    static int Main(string[] args) {
        try {
            var dllPath = args[0];
            var bamlKey = args[1];
            var outPath = args[2];
            
            // Load assembly into current domain
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
                var name = new AssemblyName(e.Name).Name;
                var dir = Path.GetDirectoryName(dllPath);
                var path = Path.Combine(dir, name + ".dll");
                if (File.Exists(path)) return Assembly.LoadFrom(path);
                return null;
            };
            
            var asm = Assembly.LoadFrom(dllPath);
            
            // Get BAML bytes
            byte[] bamlBytes = null;
            using (var resStream = asm.GetManifestResourceStream("NetSecurityScanner.Desktop.g.resources")) {
                using (var rr = new ResourceReader(resStream)) {
                    foreach (DictionaryEntry entry in rr) {
                        if (entry.Key.ToString() == bamlKey) {
                            using (var ms = new MemoryStream()) {
                                if (entry.Value is byte[] bytes) bamlBytes = bytes;
                                else if (entry.Value is Stream s) { using (s) { s.CopyTo(ms); } bamlBytes = ms.ToArray(); }
                            }
                            break;
                        }
                    }
                }
            }
            if (bamlBytes == null) { Console.Error.WriteLine("Not found"); return 1; }
            
            // Approach: Use Baml2006Reader with explicit type context
            // The trick is to provide the BAML with the BAML2006 schema that knows the assembly's types
            using (var bamlMs = new MemoryStream(bamlBytes)) {
                // First read raw baml nodes
                var bamlReader = new System.Windows.Baml2006.Baml2006Reader(bamlMs);
                
                // Use XmlWriter for output
                var xmlSettings = new XmlWriterSettings { Indent = true, OmitXmlDeclaration = true, Encoding = new UTF8Encoding(false) };
                using (var fs = File.Create(outPath))
                using (var w = XmlWriter.Create(fs, xmlSettings)) {
                    
                    // BAML has these structures: 
                    // StartObject/EndObject - elements
                    // StartMember/EndMember - properties
                    // Value - text content
                    // NamespaceDeclaration - xmlns declarations
                    
                    // We need to handle BAML-specific extensions:
                    // - ConnectionId: WPF designer only, skip
                    // - MarkupExtension: {Binding}, {StaticResource}, etc.
                    // - TypeConverter: stored as text like "System.Windows..."
                    // - DefiniteAssignment (no equivalent in XAML)
                    // - PresentationOptions:Freeze, etc.
                    
                    var nsManager = new System.Collections.Generic.Dictionary<string, string>(); // prefix -> uri
                    var prefixCounter = 0;
                    
                    while (bamlReader.Read()) {
                        switch (bamlReader.NodeType) {
                            case XamlNodeType.NamespaceDeclaration:
                                if (bamlReader.Namespace != null) {
                                    var ns = bamlReader.Namespace;
                                    if (!string.IsNullOrEmpty(ns.Namespace)) {
                                        if (string.IsNullOrEmpty(ns.Prefix)) {
                                            ns.Prefix = "auto" + (++prefixCounter);
                                        }
                                        nsManager[ns.Prefix] = ns.Namespace;
                                    }
                                }
                                break;
                            case XamlNodeType.StartObject: {
                                var t = bamlReader.Type;
                                string typeName = t.Name;
                                string typeNs = t.UnderlyingType?.Namespace ?? "clr-namespace:NetSecurityScanner";
                                if (typeNs.StartsWith("clr-namespace:")) {
                                    // Local type
                                    w.WriteStartElement(typeName);
                                    if (!nsManager.ContainsValue(typeNs)) {
                                        var pfx = "local" + (++prefixCounter);
                                        w.WriteAttributeString("xmlns", pfx, null, typeNs);
                                        nsManager[pfx] = typeNs;
                                    }
                                } else {
                                    w.WriteStartElement(typeName);
                                }
                                foreach (var kv in nsManager) {
                                    w.WriteAttributeString("xmlns", kv.Key, null, kv.Value);
                                }
                                nsManager.Clear();
                                break;
                            }
                            case XamlNodeType.EndObject:
                                w.WriteEndElement();
                                break;
                            case XamlNodeType.StartMember:
                                w.WriteStartAttribute(bamlReader.Member.Name);
                                break;
                            case XamlNodeType.EndMember:
                                w.WriteEndAttribute();
                                break;
                            case XamlNodeType.Value:
                                string val = bamlReader.Value?.ToString() ?? "";
                                w.WriteString(val);
                                break;
                        }
                    }
                }
            }
            Console.WriteLine("DONE: " + outPath);
            return 0;
        } catch (Exception ex) {
            Console.Error.WriteLine("ERROR: " + ex);
            return 1;
        }
    }
}
