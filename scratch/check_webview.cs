using System;
using System.Reflection;
using Microsoft.Web.WebView2.Core;

public class Program
{
    public static void Main()
    {
        Type type = typeof(CoreWebView2);
        Console.WriteLine($"Members of {type.Name}:");
        foreach (var member in type.GetMembers())
        {
            if (member.Name.Contains("History") || member.Name.Contains("Back") || member.Name.Contains("Forward"))
            {
                Console.WriteLine($"{member.MemberType}: {member.Name}");
            }
        }
    }
}
