using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;

namespace DNGuard_Unpacker
{
	// Token: 0x02000010 RID: 16
	internal class MethodReader : MethodBodyReaderBase
	{
		// Token: 0x06000059 RID: 89 RVA: 0x0000B404 File Offset: 0x0000A404
		public MethodReader(ModuleDefMD module, MethodsDecrypter.DecrypterBase.methodInfo mi, IList<Parameter> parameters, MethodsDecrypter.DecrypterBase db)
			: base(ByteArrayDataReaderFactory.CreateReader(mi.MethodData), parameters)
		{
			this.module = module;
			this.ehBytes = mi.MethodEH;
			if (mi.MethodEH != null)
			{
				this.ehReader = ByteArrayDataReaderFactory.CreateReader(mi.MethodEH);
			}
			this.localsArray = null;
			foreach (Local item in mi.Method_Locals)
			{
				base.Locals.Add(item);
			}
			this.decryptor = db;
			this.methodInfo = mi;
		}

		// Token: 0x0600005A RID: 90 RVA: 0x0000B4D0 File Offset: 0x0000A4D0
		protected override MethodSig ReadInlineSig(Instruction instr)
		{
			uint token = this.reader.ReadUInt32();
			MethodSig result;
			if (MDToken.ToTable(token) != Table.StandAloneSig)
			{
				result = null;
			}
			else
			{
				StandAloneSig standAloneSig = this.module.ResolveStandAloneSig(MDToken.ToRID(token), this.gpContext);
				result = ((standAloneSig != null) ? standAloneSig.MethodSig : null);
			}
			return result;
		}

		// Token: 0x0600005B RID: 91 RVA: 0x0000B530 File Offset: 0x0000A530
		public void Read(MethodDef method)
		{
			this.gpContext = GenericParamContext.Create(method);
			if (this.localsArray != null)
			{
				LocalSig localSig = (LocalSig)SignatureReader.ReadSig(this.module, this.localsArray);
				if (localSig != null)
				{
					base.SetLocals(localSig.GetLocals());
				}
			}
			base.ReadInstructions((int)this.reader.Length);
			if (this.ehBytes != null)
			{
				this.ReadExceptionHandlers(this.ehReader);
			}
		}

		// Token: 0x0600005C RID: 92 RVA: 0x0000B5B4 File Offset: 0x0000A5B4
		private T Resolve<T>(int token)
		{
			return (T)((object)this.module.ResolveToken(token, this.gpContext));
		}

		// Token: 0x0600005D RID: 93 RVA: 0x0000B5E0 File Offset: 0x0000A5E0
		protected override ITokenOperand ReadInlineTok(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.IsHVMTechnologyEnabled())
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<ITokenOperand>((int)token);
		}

		// Token: 0x0600005E RID: 94 RVA: 0x0000B640 File Offset: 0x0000A640
		protected override string ReadInlineString(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.IsHVMTechnologyEnabled())
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			string str = StringDecrypter.GetStringByToken(token);
			if (str != null)
			{
				return str;
			}
			return this.module.ReadUserString(token);
		}

		// Token: 0x0600005F RID: 95 RVA: 0x0000B6A8 File Offset: 0x0000A6A8
		protected override ITypeDefOrRef ReadInlineType(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.IsHVMTechnologyEnabled())
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<ITypeDefOrRef>((int)token);
		}

		// Token: 0x06000060 RID: 96 RVA: 0x0000B708 File Offset: 0x0000A708
		protected override IField ReadInlineField(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.IsHVMTechnologyEnabled())
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<IField>((int)token);
		}

		// Token: 0x06000061 RID: 97 RVA: 0x0000B768 File Offset: 0x0000A768
		protected override IMethod ReadInlineMethod(Instruction instr)
		{
			uint token = (uint)this.reader.ReadInt32();
			if (this.decryptor.IsHVMTechnologyEnabled())
			{
				token = this.decryptor.DecryptHVMToken(token, this.hvm_counter, this.methodInfo);
				this.hvm_counter++;
			}
			return this.Resolve<IMethod>((int)token);
		}

		// Token: 0x06000062 RID: 98 RVA: 0x0000B7C8 File Offset: 0x0000A7C8
		private void ReadExceptionHandlers(DataReader ehReader)
		{
			byte b = ehReader.ReadByte();
			bool IsFat = (b & 64) > 0;
			if (IsFat)
			{
				this.ReadFatExceptionHandlers(ref ehReader);
			}
			else if ((b & 63) == 1)
			{
				this.ReadSmallExceptionHandlers(ref ehReader);
			}
		}

		// Token: 0x06000063 RID: 99 RVA: 0x0000B818 File Offset: 0x0000A818
		private static ushort GetNumberOfExceptionHandlers(uint num)
		{
			return (ushort)num;
		}

		// Token: 0x06000064 RID: 100 RVA: 0x0000B82C File Offset: 0x0000A82C
		private void ReadFatExceptionHandlers(ref DataReader ehReader)
		{
			uint position = ehReader.Position;
			ehReader.Position = position - 1U;
			int numberOfExceptionHandlers = (int)MethodReader.GetNumberOfExceptionHandlers((ehReader.ReadUInt32() >> 8) / 24U);
			for (int i = 0; i < numberOfExceptionHandlers; i++)
			{
				ExceptionHandler exceptionHandler = new ExceptionHandler((ExceptionHandlerType)ehReader.ReadUInt32());
				uint offset = ehReader.ReadUInt32();
				exceptionHandler.TryStart = base.GetInstruction(offset);
				exceptionHandler.TryEnd = base.GetInstruction(offset + ehReader.ReadUInt32());
				offset = ehReader.ReadUInt32();
				exceptionHandler.HandlerStart = base.GetInstruction(offset);
				exceptionHandler.HandlerEnd = base.GetInstruction(offset + ehReader.ReadUInt32());
				if (exceptionHandler.HandlerType == ExceptionHandlerType.Catch)
				{
					exceptionHandler.CatchType = this.module.ResolveToken(ehReader.ReadUInt32(), this.gpContext) as ITypeDefOrRef;
				}
				else if (exceptionHandler.HandlerType == ExceptionHandlerType.Filter)
				{
					exceptionHandler.FilterStart = base.GetInstruction(ehReader.ReadUInt32());
				}
				else
				{
					ehReader.ReadUInt32();
				}
				base.Add(exceptionHandler);
			}
		}

		// Token: 0x06000065 RID: 101 RVA: 0x0000B94C File Offset: 0x0000A94C
		private void ReadSmallExceptionHandlers(ref DataReader ehReader)
		{
			int numberOfExceptionHandlers = (int)MethodReader.GetNumberOfExceptionHandlers((uint)(ehReader.ReadByte() / 12));
			ehReader.Position += 2U;
			for (int i = 0; i < numberOfExceptionHandlers; i++)
			{
				ExceptionHandler exceptionHandler = new ExceptionHandler((ExceptionHandlerType)ehReader.ReadUInt16());
				uint num = (uint)ehReader.ReadUInt16();
				exceptionHandler.TryStart = base.GetInstruction(num);
				exceptionHandler.TryEnd = base.GetInstruction(num + (uint)ehReader.ReadByte());
				num = (uint)ehReader.ReadUInt16();
				exceptionHandler.HandlerStart = base.GetInstruction(num);
				exceptionHandler.HandlerEnd = base.GetInstruction(num + (uint)ehReader.ReadByte());
				if (exceptionHandler.HandlerType == ExceptionHandlerType.Catch)
				{
					exceptionHandler.CatchType = this.module.ResolveToken(ehReader.ReadUInt32(), this.gpContext) as ITypeDefOrRef;
				}
				else if (exceptionHandler.HandlerType == ExceptionHandlerType.Filter)
				{
					exceptionHandler.FilterStart = base.GetInstruction(ehReader.ReadUInt32());
				}
				else
				{
					ehReader.ReadUInt32();
				}
				base.Add(exceptionHandler);
			}
		}

		// Token: 0x0400006C RID: 108
		private ModuleDefMD module;

		// Token: 0x0400006D RID: 109
		private GenericParamContext gpContext;

		// Token: 0x0400006E RID: 110
		private MethodsDecrypter.DecrypterBase decryptor;

		// Token: 0x0400006F RID: 111
		private MethodsDecrypter.DecrypterBase.methodInfo methodInfo;

		// Token: 0x04000070 RID: 112
		private int hvm_counter = 1;

		// Token: 0x04000071 RID: 113
		private readonly byte[] ehBytes;

		// Token: 0x04000072 RID: 114
		private readonly DataReader ehReader;

		// Token: 0x04000073 RID: 115
		private readonly byte[] localsArray;
	}
}
