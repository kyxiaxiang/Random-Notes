using System;
using System.Management.Automation.Runspaces;
using System.Text;

namespace nopowershell
{
    class Programe
    {
        static void Main(string[] args)
        {
            byte[] pscommand = Convert.FromBase64String(args[0]);
            string decodedString = Encoding.UTF8.GetString(pscommand);
            Runspace demo = RunspaceFactory.CreateRunspace();
            demo.Open();
            Pipeline pipeline = demo.CreatePipeline();
            pipeline.Commands.AddScript(decodedString);
            pipeline.Invoke();
            demo.Close();
        }

    }

}
