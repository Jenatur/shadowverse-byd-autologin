// svs-autologin launcher (phase 5, user request 2026-10-14).
//
// A double-clickable exe at the install root. All it does:
// resolve its own directory -> runtime\pythonw.exe tools\gui_app.py, fully
// detached. pythonw alone would work, but an .exe gives the Start Menu /
// desktop shortcut a real icon target and users something they recognize.
//
// Build (build_runtime.ps1 does this; csc ships with every Windows):
//   csc /nologo /target:winexe /out:svs-autologin.exe tools\launcher.cs
//
// ASCII only on purpose (console codepage roulette on other machines).

using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

static class Launcher
{
    [STAThread]
    static int Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string pythonw = Path.Combine(root, "runtime", "pythonw.exe");
        string gui = Path.Combine(root, "tools", "gui_app.py");

        if (!File.Exists(pythonw) || !File.Exists(gui))
        {
            MessageBox.Show(
                "Installation incomplete: missing\n  " + pythonw + "\nor\n  " + gui +
                "\n\nRe-extract the zip and run tools\\setup.bat again.",
                "svs-autologin",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = pythonw,
                Arguments = "\"" + gui + "\"",
                WorkingDirectory = root,
                UseShellExecute = true,   // fully detached from this launcher
            };
            Process.Start(psi);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Failed to start the GUI:\n" + ex.Message + "\n\nSee log\\gui.log.",
                "svs-autologin",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
