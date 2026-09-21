using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNGuard_Unpacker
{
	// Token: 0x0200000D RID: 13
	internal class InvalidMethodsFinder
	{
		// Token: 0x0600004B RID: 75 RVA: 0x0000A91C File Offset: 0x0000991C
		public static void Remove(ModuleDef module)
		{
			foreach (MethodDef invalidMethod in InvalidMethodsFinder.FindAll(module))
			{
				invalidMethod.DeclaringType.Remove(invalidMethod);
			}
		}

		// Token: 0x0600004C RID: 76 RVA: 0x0000A980 File Offset: 0x00009980
		public static List<MethodDef> FindAll(ModuleDef module)
		{
			List<MethodDef> list = new List<MethodDef>();
			foreach (TypeDef typeDef in module.GetTypes())
			{
				foreach (MethodDef methodDef in typeDef.Methods)
				{
					if (InvalidMethodsFinder.IsInvalidMethod(methodDef))
					{
						list.Add(methodDef);
					}
				}
			}
			return list;
		}

		// Token: 0x0600004D RID: 77 RVA: 0x0000AA4C File Offset: 0x00009A4C
		public static bool IsInvalidMethod(MethodDef method)
		{
			bool flag;
			if (method == null)
			{
				flag = false;
			}
			else if (!method.HasBody)
			{
				flag = false;
			}
			else
			{
				foreach (Instruction instruction in method.Body.Instructions)
				{
					if (instruction.OpCode.Code == Code.Ldstr)
					{
						string str = (string)instruction.Operand;
						if (str == "魇" || str == "寠" || str == "Error, DNGuard Runtime library not loaded!")
						{
							return true;
						}
					}
				}
				flag = false;
			}
			return flag;
		}
	}
}
