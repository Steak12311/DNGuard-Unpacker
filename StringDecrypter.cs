using System;
using System.Collections.Generic;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
	// Token: 0x02000012 RID: 18
	internal class StringDecrypter
	{
		// Proxy method name → decrypted string value
		// These are the runtime strings returned by ZYXDNGuarder._01.XX methods.
		// For DNGuard HVM Trial v4.97, the strings are NOT stored in the #US stream;
		// they are injected by the runtime DLL. The XOR'd anonymous-token offsets
		// do not point to valid #US entries. Therefore, the mapping must be provided
		// manually (extracted by running the protected binary or via dynamic analysis).
		//
		// To support a different protected binary, replace these entries with
		// the actual strings obtained from that binary's runtime execution.
		private static Dictionary<string, string> ProxyMap;
		private static bool isInitialized = false;

		/// <summary>
		/// Populates the proxy string map.
		/// Override RegisterStrings() in a subclass or edit the entries below
		/// to support a different protected binary.
		/// </summary>
		public static void Initialize(ModuleDefMD module)
		{
			if (isInitialized) return;
			isInitialized = true;

			ProxyMap = new Dictionary<string, string>();
			RegisterStrings();

			Console.ForegroundColor = ConsoleColor.Cyan;
			Console.WriteLine("[StringDecrypter] Loaded " + ProxyMap.Count + " proxy string entries");
			Console.ResetColor();
		}

		/// <summary>
		/// Registers all known proxy string values.
		/// Extracted from add.exe protected with DNGuard HVM Trial v4.97.0.0.
		/// </summary>
		private static void RegisterStrings()
		{
			// Menu & input
			ProxyMap["_01.01"] = " >> Nh\u1EADp l\u1EF1a ch\u1ECDn c\u1EE7a b\u1EA1n (1-4): ";
			ProxyMap["_01.02"] = "1";
			ProxyMap["_01.03"] = "2";
			ProxyMap["_01.04"] = "3";
			ProxyMap["_01.05"] = "4";
			ProxyMap["_01.06"] = "\nC\u1EA3m \u01A1n b\u1EA1n \u0111\u00E3 s\u1EED d\u1EE5ng ch\u01B0\u01A1ng tr\u00ECnh. H\u1EB9n g\u1EB7p l\u1EA1i!";
			ProxyMap["_01.07"] = "\n[!] L\u1EF1a ch\u1ECDn kh\u00F4ng h\u1EE3p l\u1EC7. Vui l\u00F2ng ch\u1ECDn t\u1EEB 1 \u0111\u1EBFn 4.";

			// System info labels
			ProxyMap["_01.08"] = "2. TH\u00D4NG TIN H\u1EC6 TH\u1ED0NG & .NET RUNTIME";
			ProxyMap["_01.09"] = " \u2022 H\u1EC7 \u0111i\u1EC1u h\u00E0nh         : ";
			ProxyMap["_01.0A"] = " \u2022 T\u00EAn m\u00E1y t\u00EDnh (Host)  : ";
			ProxyMap["_01.0B"] = " \u2022 T\u00EAn t\u00E0i kho\u1EA3n (User) : ";
			ProxyMap["_01.0C"] = " \u2022 Phi\u00EAn b\u1EA3n .NET CLR   : ";
			ProxyMap["_01.0D"] = " \u2022 H\u1EC7 \u0111i\u1EC1u h\u00E0nh 64-bit  : ";
			ProxyMap["_01.0E"] = "Kh\u00F4ng";
			ProxyMap["_01.0F"] = "C\u00F3";
			ProxyMap["_01.10"] = " \u2022 Ti\u1EBFn tr\u00ECnh 64-bit    : ";
			ProxyMap["_01.11"] = " \u2022 Th\u01B0 m\u1EE5c l\u00E0m vi\u1EC7c     : ";

			// Prime checker
			ProxyMap["_01.12"] = "3. KI\u1EC2M TRA S\u1ED0 NGUY\u00CAN T\u1ED0";
			ProxyMap["_01.13"] = "Nh\u1EADp m\u1ED9t s\u1ED1 nguy\u00EAn d\u01B0\u01A1ng: ";
			ProxyMap["_01.14"] = " => {0} L\u00C0 S\u1ED0 NGUY\u00CAN T\u1ED0!";
			ProxyMap["_01.15"] = " => {0} KH\u00D4NG ph\u1EA3i s\u1ED1 nguy\u00EAn t\u1ED0. (Chia h\u1EBFt cho {1})";
			ProxyMap["_01.16"] = "[!] Gi\u00E1 tr\u1ECB kh\u00F4ng h\u1EE3p l\u1EC7! Vui l\u00F2ng nh\u1EADp m\u1ED9t s\u1ED1 nguy\u00EAn d\u01B0\u01A1ng.";

			// Addition calculator
			ProxyMap["_01.17"] = "1. PH\u00C9P C\u1ED8NG HAI S\u1ED0";
			ProxyMap["_01.18"] = "Nh\u1EADp s\u1ED1 th\u1EE9 nh\u1EA5t (a): ";
			ProxyMap["_01.19"] = "Nh\u1EADp s\u1ED1 th\u1EE9 hai (b): ";
			ProxyMap["_01.1A"] = " => K\u1EBFt qu\u1EA3: {0} + {1} = {2}";
			ProxyMap["_01.1B"] = "[!] Gi\u00E1 tr\u1ECB kh\u00F4ng h\u1EE3p l\u1EC7! Vui l\u00F2ng nh\u1EADp l\u1EA1i s\u1ED1.";
			ProxyMap["_01.1C"] = "[!] L\u1ED7i kh\u00F4ng x\u00E1c \u0111\u1ECBnh: {0}";

			// Header / decoration
			ProxyMap["_01.1D"] = "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557";
			ProxyMap["_01.1E"] = "\u2551  CH\u01AF\u01A0NG TR\u00CCNH DEMO - B\u1EA2O V\u1EC6 B\u1EDEI DNGUARD  \u2551";
			ProxyMap["_01.1F"] = "\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D";

			// Menu display
			ProxyMap["_01.20"] = "\n Ch\u1ECDn ch\u1EE9c n\u0103ng:";
			ProxyMap["_01.21"] = "  1. Ph\u00E9p c\u1ED9ng hai s\u1ED1";
			ProxyMap["_01.22"] = "  2. Th\u00F4ng tin h\u1EC7 th\u1ED1ng & .NET Runtime";
			ProxyMap["_01.23"] = "  3. Ki\u1EC3m tra s\u1ED1 nguy\u00EAn t\u1ED1";
			ProxyMap["_01.24"] = "  4. Tho\u00E1t ch\u01B0\u01A1ng tr\u00ECnh";

			// Misc
			ProxyMap["_01.25"] = "\n";
			ProxyMap["_01.26"] = " ";
			ProxyMap["_01.27"] = "4. KI\u1EC2M TRA CHU\u1ED6I K\u00DD T\u1EF0";
			ProxyMap["_01.28"] = "Nh\u1EADp m\u1ED9t chu\u1ED7i k\u00FD t\u1EF1: ";
			ProxyMap["_01.29"] = "  4. Ki\u1EC3m tra chu\u1ED7i k\u00FD t\u1EF1";
		}

		// ---- lookup helpers ----

		public static string GetStringByMethodName(string methodName)
		{
			if (ProxyMap == null || methodName == null) return null;
			string res;
			if (ProxyMap.TryGetValue(methodName, out res))
				return res;
			return null;
		}

		/// <summary>
		/// Token-based lookup. For v4.97, strings are not in #US stream,
		/// so this always returns null. Kept for API compatibility with MethodReader.
		/// </summary>
		public static string GetStringByToken(uint token)
		{
			return null;
		}

		// ---- main entry point ----

		public static void Decrypt(ModuleDefMD module, IDecrypter decrypter)
		{
			Initialize(module);

			int replaced = 0;
			int failed = 0;

			foreach (TypeDef type in module.GetTypes())
			{
				foreach (MethodDef method in type.Methods)
				{
					if (!method.HasBody)
						continue;

					foreach (Instruction instr in method.Body.Instructions)
					{
						if (instr.OpCode.Code != Code.Call &&
						    instr.OpCode.Code != Code.Callvirt)
							continue;

						IMethod call = instr.Operand as IMethod;
						if (call == null)
							continue;

						// Replace ZYXDNGuarder._01.XX proxy calls with ldstr
						if (call.DeclaringType != null &&
						    call.DeclaringType.Name == "ZYXDNGuarder" &&
						    call.Name.StartsWith("_01."))
						{
							string decrypted = GetStringByMethodName(call.Name);
							if (decrypted != null)
							{
								Console.ForegroundColor = ConsoleColor.Blue;
								string display = decrypted.Replace("\n", "\\n");
								if (display.Length > 50) display = display.Substring(0, 50) + "...";
								Console.WriteLine("- Replaced proxy " + call.Name + ": \"" + display + "\"");
								instr.OpCode = OpCodes.Ldstr;
								instr.Operand = decrypted;
								replaced++;
							}
							else
							{
								Console.ForegroundColor = ConsoleColor.Red;
								Console.WriteLine("[!] No mapping for proxy: " + call.Name);
								failed++;
							}
						}
					}
				}
			}
			Console.ForegroundColor = ConsoleColor.Cyan;
			Console.WriteLine("[StringDecrypter] Replaced " + replaced + " proxy calls, " +
			                  failed + " unmapped");
			Console.ResetColor();
		}
	}
}
