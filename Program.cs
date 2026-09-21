using System;
using System.IO;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace DNGuard_Unpacker
{
	// Token: 0x02000011 RID: 17
	internal class Program
	{
		// Token: 0x06000066 RID: 102 RVA: 0x0000BA64 File Offset: 0x0000AA64
		private static void Main(string[] args)
		{
			Console.Title = "DNGuard Static Unpacker";
			if (args != null && args.Length > 0)
			{
				Program.path = args[0];
			}
			else
			{
				Console.WriteLine("Warning: no file specified to the program");
				Console.WriteLine("start it by DNGuard Static Unpacker.exe file_to_unpack");
				Program.path = "C:\\framework_Protected_3.9.0\\FrameworkChanger.exe";
				if (!File.Exists(Program.path))
				{
					Environment.Exit(0);
				}
			}
			Console.WriteLine(Program.path);
			string originalPath = Program.path;
			Program.path = ContainerExtractor.ExtractIfPacked(Program.path);
			byte[] buffer = File.ReadAllBytes(Program.path);
			Program.module = ModuleDefMD.Load(Program.path, (ModuleContext)null);
			MethodsDecrypter methodsDecrypter = new MethodsDecrypter(Program.module);
			Program.ShouldPrint = true;
			methodsDecrypter.Find();
			Thread.Sleep(3000);
			methodsDecrypter.DecryptInternal(ref buffer);
			Program.module = ModuleDefMD.Load(buffer, (ModuleContext)null);
			methodsDecrypter = new MethodsDecrypter(Program.module);
			methodsDecrypter.Find();
			methodsDecrypter.Decrypt();
			MethodDef initializeMethod = methodsDecrypter.InitializeMethod;
			Program.RemoveAllCalls(Program.module, initializeMethod);
			StringDecrypter.Decrypt(Program.module, methodsDecrypter.decrypter);
			InvalidMethodsFinder.Remove(Program.module);
			Program.Save(originalPath, Program.module);
		}

		// Token: 0x06000067 RID: 103 RVA: 0x0000BB88 File Offset: 0x0000AB88
		private static void RemoveAllCalls(ModuleDef module, MethodDef initializeMethod)
		{
			foreach (TypeDef type in module.GetTypes())
			{
				foreach (MethodDef method in type.Methods)
				{
					if (method.HasBody)
					{
						foreach (Instruction instr in method.Body.Instructions)
						{
							if (instr.Operand is IMethod)
							{
								IMethod mDef = instr.Operand as IMethod;
								if (mDef != null)
								{
									bool isInit = (initializeMethod != null && mDef == initializeMethod) ||
									              (mDef.DeclaringType != null && mDef.DeclaringType.FullName.Contains("ZYXDNGuarder") && (mDef.Name == "Startup" || mDef.Name == "Execute"));
									if (isInit)
									{
										instr.OpCode = OpCodes.Nop;
										instr.Operand = null;
									}
								}
							}
						}
					}
				}
			}

			TypeDef zyx = module.Find("ZYXDNGuarder", false);
			if (zyx != null)
			{
				foreach (MethodDef m in zyx.Methods)
				{
					if (m.Name == ".cctor" && m.HasBody)
					{
						m.Body.Instructions.Clear();
						m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
					}
				}
			}
		}

		// Token: 0x06000068 RID: 104 RVA: 0x0000BCE0 File Offset: 0x0000ACE0
		private static void Save(string location, ModuleDefMD module)
		{
			Console.ForegroundColor = ConsoleColor.Green;
			Console.WriteLine("- Saving module...");
			NativeModuleWriterOptions Writer = new NativeModuleWriterOptions(module, true)
			{
				KeepExtraPEData = true,
				KeepWin32Resources = true,
				Logger = DummyLogger.NoThrowInstance
			};
			Writer.MetadataOptions.Flags = MetadataFlags.PreserveTypeRefRids | MetadataFlags.PreserveTypeDefRids | MetadataFlags.PreserveFieldRids | MetadataFlags.PreserveMethodRids | MetadataFlags.PreserveParamRids | MetadataFlags.PreserveMemberRefRids | MetadataFlags.PreserveStandAloneSigRids | MetadataFlags.PreserveEventRids | MetadataFlags.PreservePropertyRids | MetadataFlags.PreserveTypeSpecRids | MetadataFlags.PreserveMethodSpecRids | MetadataFlags.PreserveStringsOffsets | MetadataFlags.PreserveBlobOffsets | MetadataFlags.PreserveExtraSignatureData | MetadataFlags.KeepOldMaxStack;
			string path = string.Concat(new string[]
			{
				Path.GetDirectoryName(location),
				"\\",
				Path.GetFileNameWithoutExtension(location),
				"-NoDNG",
				Path.GetExtension(location)
			});
			module.NativeWrite(path, Writer);
			Console.WriteLine("- Saved to: " + path);
		}

		// Token: 0x04000074 RID: 116
		public static string path = "";

		// Token: 0x04000075 RID: 117
		public static bool ShouldPrint = false;

		// Token: 0x04000076 RID: 118
		public static ModuleDefMD module;
	}
}
