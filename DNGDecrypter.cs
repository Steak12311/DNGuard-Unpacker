using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;
using dnlib.PE;

namespace DNGuard_Unpacker
{
	// Token: 0x0200000C RID: 12
	public class DNGDecrypter : MethodsDecrypter.DecrypterBase
	{
		// Token: 0x0600003A RID: 58 RVA: 0x00004F45 File Offset: 0x00003F45
		public DNGDecrypter(ModuleDefMD module)
			: base(module)
		{
		}

		// Token: 0x0600003B RID: 59 RVA: 0x00004F58 File Offset: 0x00003F58
		public int GetStructSize(int size, ref byte[] array)
		{
			this.reader.Position = this.DataOffset;
			array = this.reader.ReadBytes(size);
			uint[] dst = new uint[array.Length / 4];
			Buffer.BlockCopy(array, 0, dst, 0, array.Length);
			Adler32 adler = new Adler32();
			adler.Update(array);
			int num;
			if ((ulong)this.MetaDataValue[2] == (ulong)adler.Value)
			{
				num = size;
			}
			else
			{
				num = 0;
			}
			return num;
		}

		// Token: 0x0600003C RID: 60 RVA: 0x00004FD4 File Offset: 0x00003FD4
		public void PrintInformation()
		{
			Console.WriteLine("Value1=" + DNGDecrypter.GetHexBytes(this.value1) + " Value3=" + DNGDecrypter.GetHexBytes(this.value3));
			Console.WriteLine("ProtectionSettings=" + this.DataStructure.ProtectionSettings.ToString("X8"));
			if ((this.DataStructure.ProtectionSettings & 512U) != 0U)
			{
				Console.WriteLine("Avoid ilegal jit action is enabled!");
			}
			else
			{
				Console.WriteLine("Avoid ilegal jit action is disabled!");
			}
			Console.WriteLine("ProtectionFeatures=" + this.DataStructure.ProtectionFeatures.ToString());
			bool isEnterprise = base.IsHVMTechnologyEnabled();
			Console.WriteLine("- Version: " + (isEnterprise ? "Enterprise" : "Professional"));
		}

		// Token: 0x0600003D RID: 61 RVA: 0x000050B0 File Offset: 0x000040B0
		public static string GetHexBytes(uint value1)
		{
			byte[] bytes = BitConverter.GetBytes(value1);
			return BitConverter.ToString(bytes).Replace("-", string.Empty);
		}

		// Token: 0x0600003E RID: 62 RVA: 0x000050E0 File Offset: 0x000040E0
		public static uint GetMaximProtectSettings()
		{
			return 4067U;
		}

		// Token: 0x0600003F RID: 63 RVA: 0x000050F8 File Offset: 0x000040F8
		public static int CountBits(uint value)
		{
			int count = 0;
			while (value != 0U)
			{
				count++;
				value &= value - 1U;
			}
			return count;
		}

		// Token: 0x06000040 RID: 64 RVA: 0x00005128 File Offset: 0x00004128
		public override void ParseStructure()
		{
			if (this.DataSection != null)
			{
				bool print_helpfull = false;
				for (int i = 4; i < 400; i += 4)
				{
					this.reader.Position = this.DataOffset;
					byte[] array2 = this.reader.ReadBytes(i);
					uint[] dst2 = new uint[array2.Length / 4];
					Buffer.BlockCopy(array2, 0, dst2, 0, array2.Length);
					Adler32 adler = new Adler32();
					adler.Update(array2);
					if ((ulong)this.MetaDataValue[2] == (ulong)adler.Value)
					{
						if (Program.ShouldPrint)
						{
							Console.WriteLine("Generic finded struct size=" + i.ToString());
						}
					}
				}
				byte[] array3 = null;
				this.StructSize = this.GetStructSize(104, ref array3);
				if (this.StructSize == 0)
				{
					this.StructSize = this.GetStructSize(108, ref array3);
				}
				if (this.StructSize == 0)
				{
					this.StructSize = this.GetStructSize(112, ref array3);
				}
				if (this.StructSize == 0)
				{
					this.StructSize = this.GetStructSize(124, ref array3);
				}
				if (this.StructSize == 0)
				{
					this.StructSize = this.GetStructSize(128, ref array3);
				}
				if (this.StructSize == 0)
				{
					this.StructSize = this.GetStructSize(152, ref array3);
				}
				if (this.StructSize == 0)
				{
					this.StructSize = this.GetStructSize(160, ref array3);
				}
				if (Program.ShouldPrint)
				{
					if (this.StructSize == 0)
					{
						Console.WriteLine("Failed to find struct size, unknown version!");
					}
					else if (this.StructSize == 104)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " =v3.97/3.98/3.99 v4.0");
					}
					else if (this.StructSize == 108)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " =v4.30");
					}
					else if (this.StructSize == 112)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " =v4.12-4.20");
					}
					else if (this.StructSize == 124)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " =v4.60-4.80");
					}
					else if (this.StructSize == 128)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " =v3.70/3.72/3.73/3.82");
					}
					else if (this.StructSize == 152)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " =v3.90");
					}
					else if (this.StructSize == 160)
					{
						Console.WriteLine("Struct size=" + this.StructSize.ToString() + " Enterprise registered !=v3.97/98/99 !=4.80");
					}
				}
				this.version = "";
				if (MethodsDecrypter.NativeModulePath32 != null && MethodsDecrypter.NativeModulePath32 != "" && File.Exists(MethodsDecrypter.NativeModulePath32))
				{
					FileVersionInfo ver = FileVersionInfo.GetVersionInfo(MethodsDecrypter.NativeModulePath32);
					this.version = string.Format("{0}.{1}.{2}.{3}", new object[] { ver.FileMajorPart, ver.FileMinorPart, ver.FileBuildPart, ver.FilePrivatePart });
				}
				if (string.IsNullOrEmpty(this.version))
				{
					string unpackerDir = AppDomain.CurrentDomain.BaseDirectory;
					string cand1 = Path.Combine(unpackerDir, "HVMRuntm.dll");
					string cand2 = @"C:\Program Files (x86)\DNGuard Trial\HVMRuntm.dat";
					string cand3 = @"C:\Program Files\DNGuard Trial\HVMRuntm.dat";
					string targetDll = null;
					if (File.Exists(cand1)) targetDll = cand1;
					else if (File.Exists(cand2)) targetDll = cand2;
					else if (File.Exists(cand3)) targetDll = cand3;

					if (targetDll != null)
					{
						try
						{
							FileVersionInfo ver = FileVersionInfo.GetVersionInfo(targetDll);
							this.version = string.Format("{0}.{1}.{2}.{3}", new object[] { ver.FileMajorPart, ver.FileMinorPart, ver.FileBuildPart, ver.FilePrivatePart });
						}
						catch { }
					}
					if (string.IsNullOrEmpty(this.version) && this.StructSize == 124)
					{
						this.version = "4.97.0.0";
					}
				}
				using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(array3)))
				{
					if (this.StructSize == 104)
					{
						if (this.version.StartsWith("3.9.7"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							ushort useless = binaryReader.ReadUInt16();
							this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint useless2 = binaryReader.ReadUInt32();
							uint useless3 = binaryReader.ReadUInt32();
							uint useless4 = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							uint useless5 = binaryReader.ReadUInt32();
							uint useless6 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							uint useless7 = binaryReader.ReadUInt32();
							uint useless8 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint useless9 = binaryReader.ReadUInt32();
						}
						else if (this.version.StartsWith("3.9.8"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							ushort useless = binaryReader.ReadUInt16();
							this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint useles2 = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint usless4 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint usless6 = binaryReader.ReadUInt32();
							uint usless7 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							uint usless10 = binaryReader.ReadUInt32();
						}
						else if (this.version.StartsWith("3.9.9"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							ushort useless = binaryReader.ReadUInt16();
							this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint useles2 = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint usless4 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint usless6 = binaryReader.ReadUInt32();
							uint usless7 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							uint usless10 = binaryReader.ReadUInt32();
						}
						else if (this.version.StartsWith("4.0"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							ushort useless = binaryReader.ReadUInt16();
							this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint useles2 = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint usless4 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint usless6 = binaryReader.ReadUInt32();
							uint usless7 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							uint usless10 = binaryReader.ReadUInt32();
						}
					}
					else if (this.StructSize == 108)
					{
						if (this.version.StartsWith("4.3"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							uint useless10 = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							uint useless2 = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint useless4 = binaryReader.ReadUInt32();
							uint useless7 = binaryReader.ReadUInt32();
							uint usless7 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							uint uselss11 = binaryReader.ReadUInt32();
							uint uselss12 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint uselss13 = binaryReader.ReadUInt32();
						}
					}
					else if (this.StructSize == 112)
					{
						if (this.version.StartsWith("4.1.3"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							uint useless10 = binaryReader.ReadUInt32();
							uint useless2 = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint useless7 = binaryReader.ReadUInt32();
							uint useless8 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							uint uselss11 = binaryReader.ReadUInt32();
							uint uselss12 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint uselss13 = binaryReader.ReadUInt32();
						}
						else if (this.version.StartsWith("4.1"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							uint useless2 = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							uint useless7 = binaryReader.ReadUInt32();
							uint useless8 = binaryReader.ReadUInt32();
							uint usless6 = binaryReader.ReadUInt32();
							uint usless7 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint usless10 = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = 0U;
							this.DataStructure.ResourceCount = 0U;
						}
					}
					else if (this.StructSize == 124)
					{

						if (this.version.StartsWith("4.5.1"))
						{
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.value2 = this.value3;
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							uint unknows = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint useless4 = binaryReader.ReadUInt32();
							uint useless5 = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint useless2 = binaryReader.ReadUInt32();
							uint unknownnewval = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint useless7 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint useless8 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless8 = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							uint uselss11 = binaryReader.ReadUInt32();
							uint uselss12 = binaryReader.ReadUInt32();
							uint uselss13 = binaryReader.ReadUInt32();
							uint usless11 = binaryReader.ReadUInt32();
						}
						else if (this.version.StartsWith("4.8"))
						{

							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.value2 = this.value3;
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							uint unknown = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							uint useless2 = binaryReader.ReadUInt32();
							uint useless4 = binaryReader.ReadUInt32();
							uint useless5 = binaryReader.ReadUInt32();
							uint useless6 = binaryReader.ReadUInt32();
							uint useless7 = binaryReader.ReadUInt32();
							uint useless1e = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							uint unknwom = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint useless8 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint usless9 = binaryReader.ReadUInt32();
							uint uselss11 = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							uint uselss13 = binaryReader.ReadUInt32();
							uint usless11 = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = 0U;
						}
						else if (this.version.StartsWith("4.9") || (array3 != null && array3.Length >= 4 && BitConverter.ToUInt32(array3, 0) == 0x0020007C))
						{

							this.version = "4.97.0.0";
							this.valueN4 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							uint useless02 = binaryReader.ReadUInt32();
							uint useless03 = binaryReader.ReadUInt32();
							uint useless04 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							uint useless06 = binaryReader.ReadUInt32();
							uint encDword = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = 0U;
							uint useless08 = binaryReader.ReadUInt32();
							uint runHvmRva = binaryReader.ReadUInt32();
							uint useless10 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							uint v12 = binaryReader.ReadUInt32();
							uint v13 = binaryReader.ReadUInt32();
							uint useless14 = binaryReader.ReadUInt32();
							uint useless15 = binaryReader.ReadUInt32();
							uint useless16 = binaryReader.ReadUInt32();
							uint useless17 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							uint useless21 = binaryReader.ReadUInt32();
							uint v22 = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							uint useless24 = binaryReader.ReadUInt32();
							uint useless25 = binaryReader.ReadUInt32();
							uint useless26 = binaryReader.ReadUInt32();
							uint useless27 = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							uint useless29 = binaryReader.ReadUInt32();
							uint v30 = binaryReader.ReadUInt32();

							this.value1 = this.value3;
							this.value2 = this.value3;
							this.DataStructure.KeyBuffOffset = (v12 ^ this.value3 ^ v22) & 0x0FFFFFFFU;
							this.DataStructure.MethodsDataOffset = this.DataStructure.KeyBuffOffset;
							this.DataStructure.MethodsBufferLength = this.UncompressedMethodsBufferLength;
							this.DataStructure.ResourceCount = 0U;
							this.DataStructure.StringsOffset = 0U;
							this.DataStructure.EncryptedStringsSize = 0U;
						}
					}
					else if (this.StructSize == 152)
					{
						if (this.version.StartsWith("3.9.0"))
						{
							uint wtf = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							uint usless12 = binaryReader.ReadUInt32();
							this.valueN4 = binaryReader.ReadUInt32();
							uint usless3 = binaryReader.ReadUInt32();
							uint usless4 = binaryReader.ReadUInt32();
							uint usless5 = binaryReader.ReadUInt32();
							uint num = (this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32());
							uint usless6 = binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							uint usless7 = binaryReader.ReadUInt32();
							num = (this.DataStructure.MethodsCount = binaryReader.ReadUInt32());
							uint usless9 = binaryReader.ReadUInt32();
							uint usless10 = binaryReader.ReadUInt32();
							uint usless13 = binaryReader.ReadUInt32();
							this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
							uint usless14 = binaryReader.ReadUInt32();
							uint usless13_2 = binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							uint usless11 = binaryReader.ReadUInt32();
							uint usless15 = binaryReader.ReadUInt32();
							uint usless16 = binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							uint usless17 = binaryReader.ReadUInt32();
							uint usless18 = binaryReader.ReadUInt32();
							uint usless19 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							uint usless20 = binaryReader.ReadUInt32();
						}
					}
					else if (this.StructSize == 160)
					{
						if (this.version.StartsWith("3.9.4"))
						{
							binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
						}
						if (this.version.StartsWith("3.9.5"))
						{
							binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
						}
						else if (this.version.StartsWith("3.9.6"))
						{
							binaryReader.ReadUInt32();
							this.value3 = binaryReader.ReadUInt32();
							this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
							this.value1 = binaryReader.ReadUInt32();
							this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
							this.DataStructure.LEHSize = binaryReader.ReadUInt32();
							this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
							this.DataStructure.ResourceCount = binaryReader.ReadUInt32();
							this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.DataStructure.LocalsAndEHOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.LEHLocalsOffset = binaryReader.ReadUInt32();
							this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.HvmTokenTableOffset = binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							binaryReader.ReadUInt32();
							this.value2 = binaryReader.ReadUInt32();
							this.HvmTokenTableSize = binaryReader.ReadUInt32();
						}
					}
					if (this.StructSize == 128)
					{
						this.valueN4 = binaryReader.ReadUInt32();
						this.value3 = binaryReader.ReadUInt32();
						this.DataStructure.Encryption_Dword = binaryReader.ReadUInt32();
						this.value1 = binaryReader.ReadUInt32();
						this.DataStructure.ResourceStructureOffset = binaryReader.ReadUInt32();
						binaryReader.ReadUInt16();
						this.DataStructure.ResourceCount = (uint)binaryReader.ReadUInt16();
						this.DataStructure.MethodsDataOffset = binaryReader.ReadUInt32();
						this.DataStructure.KeyBuffOffset = binaryReader.ReadUInt32();
						this.UncompressedMethodsBufferLength = binaryReader.ReadUInt32();
						this.DataStructure.StringsOffset = binaryReader.ReadUInt32();
						this.DataStructure.LEHSize = binaryReader.ReadUInt32();
						this.DataStructure.MethodsBufferLength = binaryReader.ReadUInt32();
						this.value2 = binaryReader.ReadUInt32();
						this.DataStructure.MethodsCount = binaryReader.ReadUInt32();
						uint useless10 = binaryReader.ReadUInt32();
						uint useless2 = binaryReader.ReadUInt32();
						uint useless3 = binaryReader.ReadUInt32();
						this.LEHLocalsOffset = binaryReader.ReadUInt32();
						uint useless4 = binaryReader.ReadUInt32();
						uint useless5 = binaryReader.ReadUInt32();
						this.HvmTokenTableOffset = binaryReader.ReadUInt32();
						this.DataStructure.EncryptedStringsSize = binaryReader.ReadUInt32();
						uint useless6 = binaryReader.ReadUInt32();
						uint useless7 = binaryReader.ReadUInt32();
						this.HvmTokenTableSize = binaryReader.ReadUInt32();
						uint useless8 = binaryReader.ReadUInt32();
						this.valueN5 = 0U;
						if (this.StructSize >= 124)
						{
							uint useless9 = binaryReader.ReadUInt32();
							uint useless11 = binaryReader.ReadUInt32();
							uint useless12 = binaryReader.ReadUInt32();
							uint useless13 = binaryReader.ReadUInt32();
							this.valueN5 = binaryReader.ReadUInt32();
						}
						long Pos = binaryReader.BaseStream.Position;
					}
				}
				if (this.version.StartsWith("4.9"))
				{
					this.DataStructure.ProtectionSettings = 0U;
					this.DataStructure.ProtectionFeatures = 0;
				}
				else if (this.version.StartsWith("3.9.0"))
				{
					this.DataStructure.ProtectionSettings = this.value1 ^ this.value3 ^ this.valueN4 ^ this.DataStructure.Encryption_Dword;
					this.DataStructure.ProtectionFeatures = (MethodsDecrypter.DecrypterBase.ProtectSettings)(this.DataStructure.ProtectionSettings & 4095U);
				}
				else
				{
					this.DataStructure.ProtectionSettings = this.value1 ^ this.value3 ^ this.DataStructure.Encryption_Dword;
					this.DataStructure.ProtectionFeatures = (MethodsDecrypter.DecrypterBase.ProtectSettings)(this.DataStructure.ProtectionSettings & 4095U);
				}
				if (!this.version.StartsWith("4.9"))
				{
					this.DataStructure.MethodsDataOffset = this.DataStructure.MethodsDataOffset ^ this.value2;
				}
				if (this.version.StartsWith("3.9.5") || this.version.StartsWith("3.9.6"))
				{
					this.DataStructure.LocalsAndEHOffset = this.DataStructure.LocalsAndEHOffset ^ (this.value3 ^ this.DataStructure.Encryption_Dword);
				}
				if (!this.version.StartsWith("4.9") && this.StructSize >= 124 && (this.DataStructure.ProtectionSettings & 4294901760U) != 0U)
				{
					Console.WriteLine("Other version type");
					this.DataStructure.ProtectionSettings = this.valueN4 ^ this.valueN5 ^ this.value3 ^ this.DataStructure.Encryption_Dword;
					this.DataStructure.ProtectionFeatures = (MethodsDecrypter.DecrypterBase.ProtectSettings)(this.DataStructure.ProtectionSettings & 4095U);
				}
				if (Program.ShouldPrint)
				{
					if (print_helpfull)
					{
						string logpath = "C:\\framework_Protected_3.9.7\\structs_logs.txt";
						DNGDecrypter.ivalues = new uint[this.StructSize / 4];
						int zerosCount = 0;
						File.AppendAllText(logpath, Program.path + Environment.NewLine);
						for (int i = 0; i < this.StructSize; i += 4)
						{
							DNGDecrypter.ivalues[i / 4] = BitConverter.ToUInt32(array3, i);
							if (DNGDecrypter.ivalues[i / 4] == 0U)
							{
								zerosCount++;
							}
							File.AppendAllText(logpath, string.Concat(new string[]
							{
								(i / 4).ToString(),
								"=",
								DNGDecrypter.ivalues[i / 4].ToString(),
								" ",
								DNGDecrypter.ivalues[i / 4].ToString("X8"),
								Environment.NewLine
							}));
						}
						this.DataStructure.MethodsCount = 37U;
						List<uint> oldValues = new List<uint>();
						for (int i = 0; i < DNGDecrypter.ivalues.Length; i++)
						{
							for (int j = 0; j < DNGDecrypter.ivalues.Length; j++)
							{
								for (int k = 0; k < DNGDecrypter.ivalues.Length; k++)
								{
									for (int l = 0; l < DNGDecrypter.ivalues.Length; l++)
									{
										if (DNGDecrypter.ivalues[i] != 0U && DNGDecrypter.ivalues[j] != 0U)
										{
											if (i != j)
											{
												break;
											}
										}
									}
								}
							}
						}
						File.AppendAllText(logpath, zerosCount.ToString() + Environment.NewLine);
					}
					Console.WriteLine("in trial version Encryption_Dword, HvmTokenTableOffset, HvmTokenTableSize will be zero");
					this.PrintInformation();
					Console.WriteLine("Encryption_Dword: " + this.DataStructure.Encryption_Dword);
					Console.WriteLine("Methods_Offset: " + this.DataStructure.MethodsDataOffset);
					Console.WriteLine("KeyBuffOffset: " + this.DataStructure.KeyBuffOffset);
					Console.WriteLine("UncompressedMethodsBufferLength: " + this.UncompressedMethodsBufferLength);
					Console.WriteLine("StringsOffset: " + this.DataStructure.StringsOffset);
					Console.WriteLine("LEHSize: " + this.DataStructure.LEHSize);
					Console.WriteLine("MethodsBufferLength: " + this.DataStructure.MethodsBufferLength);
					Console.WriteLine("MethodsCount: " + this.DataStructure.MethodsCount);
					Console.WriteLine("LEHLocalsOffset: " + this.LEHLocalsOffset);
					Console.WriteLine("HvmTokenTableOffset: " + this.HvmTokenTableOffset);
					Console.WriteLine("HvmTokenTableSize: " + this.HvmTokenTableSize);
					Program.ShouldPrint = false;
					try
					{
						Console.WriteLine("Press Enter key to try to decrypt or any other key to exit");
						if (Console.ReadKey().Key != ConsoleKey.Enter)
						{
							Environment.Exit(0);
						}
					}
					catch (InvalidOperationException)
					{
					}
				}
				if (base.IsEnterpriseEdition())
				{
					this.DataStructure.KeyBuffOffset = this.DataStructure.KeyBuffOffset ^ this.DataStructure.Encryption_Dword;
					if (this.DataStructure.KeyBuffOffset > 0U)
					{
						this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
						this.KeyBuff = this.reader.ReadBytes(20);
						this.DataStructure.LocalsAndEHOffset = this.DataStructure.LocalsAndEHOffset ^ this.DataStructure.ProtectionSettings;
						this.DataStructure.MethodsDataOffset = this.DataStructure.MethodsDataOffset ^ this.DataStructure.ProtectionSettings;
						if (!base.VerifyKeyBuffer(this.KeyBuff, this.DataStructure.Encryption_Dword))
						{
							throw new Exception("Invalid key buffer!");
						}
						Array.Resize<byte>(ref this.KeyBuff, 16);
					}
				}
			}
		}

		// Token: 0x06000041 RID: 65 RVA: 0x0000742C File Offset: 0x0000642C
		public void ReadMethodsTesting(uint methodOffset, uint lehOffset)
		{
			if (base.IsApplicationMode())
			{
				throw new NotImplementedException();
			}
			if (this.version.StartsWith("3.9.7") || this.version.StartsWith("4.0") || this.version.StartsWith("4.1") || this.version.StartsWith("4.3") || this.version.StartsWith("4.5.1") || this.version.StartsWith("4.8") || this.version.StartsWith("4.9"))
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)methodOffset);
				this.DataStructure._MethodsOffsetTable = this.reader.ReadBytes((int)(this.DataStructure.MethodsCount * 4U));
				this.DataStructure._MethodsData = this.reader.ReadBytes((int)this.DataStructure.MethodsBufferLength);
				uint rva = (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)this.DataStructure.MethodsDataOffset);
				if (this.DataStructure.LEHSize <= 0U)
				{
					throw new Exception("LEHSize can't be zero!");
				}
				this.DataStructure.LEH = this.reader.ReadBytes((int)this.DataStructure.LEHSize);
				if (this.DataStructure.LEH[0] == 0 && this.DataStructure.LEH[1] == 0)
				{
					throw new Exception("Invalid LEH!");
				}
			}
			else
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)lehOffset);
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = this.reader.ReadBytes((int)this.DataStructure.LEHSize);
				}
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
				this.DataStructure._MethodsOffsetTable = this.reader.ReadBytes((int)(this.DataStructure.MethodsCount * 4U));
				this.DataStructure._MethodsData = this.reader.ReadBytes((int)this.DataStructure.MethodsBufferLength);
			}
			if (base.IsEnterpriseEdition())
			{
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = new LZAri().Decode(this.DataStructure.LEH);
					base.DecryptPrevXor(this.DataStructure.LEH, this.KeyBuff);
				}
				this.DataStructure._MethodsData = new LZAri().Decode(this.DataStructure._MethodsData);
				if ((long)this.DataStructure._MethodsData.Length != (long)((ulong)this.UncompressedMethodsBufferLength))
				{
					throw new Exception("Invalid methods buffer!");
				}
				base.DecryptPrevXor(this.DataStructure._MethodsOffsetTable, this.KeyBuff);
				if (base.IsHVMTechnologyEnabled())
				{
					this.HvmTable = this.ReadHVMTable();
					base.XorSelf(this.DataStructure._MethodsOffsetTable, 0, 20);
				}
				this.InitializeEncryptionKeys();
			}
			else
			{
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = Compressor.Decompress(this.DataStructure.LEH);
					base.DecryptXor(this.DataStructure.LEH, this.KeyBuff);
				}
				base.DecryptXor(this.DataStructure._MethodsData, this.KeyBuff);
				base.DecryptXor(this.DataStructure._MethodsOffsetTable, this.KeyBuff);
			}
			uint[] MethodsOffsets = new uint[this.DataStructure.MethodsCount];
			Buffer.BlockCopy(this.DataStructure._MethodsOffsetTable, 0, MethodsOffsets, 0, this.DataStructure._MethodsOffsetTable.Length);
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(this.DataStructure._MethodsData)))
			{
				int i = 0;
				while (i < MethodsOffsets.Length)
				{
					if ((i == 0 || i == 1) && MethodsOffsets[i] == 0U)
					{
						throw new Exception("Invalid MethodOffset");
					}
					if (MethodsOffsets[i] != 0U)
					{
						if (MethodsOffsets[i] >> 24 == 248U)
						{
							this._anonymous_tokens.Add((uint)(i + 1), (uint)((ulong)(MethodsOffsets[i] & 16777215U) ^ (ulong)((long)(i + 1))));
						}
						else
						{
							this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)MethodsOffsets[i]);
							if (this.reader.Position == 0U)
							{
								throw new Exception("Position wrong");
							}
							if (this.reader.ReadByte() != 254)
							{
								throw new Exception("First byte missing!");
							}
							MethodsDecrypter.DecrypterBase.methodInfo methodInfo2 = new MethodsDecrypter.DecrypterBase.methodInfo
							{
								DecryptorType = this.reader.ReadByte(),
								MDToken = new MDToken(i + 1),
								MethodDataOffset = this.reader.ReadUInt32(),
								Method = this.module.ResolveMethod((uint)(i + 1))
							};
							binaryReader.BaseStream.Position = (long)((ulong)methodInfo2.MethodDataOffset);
							if (binaryReader.BaseStream.Position == 0L)
							{
								throw new Exception("Position wrong");
							}
							if (methodInfo2.DecryptorType > 14)
							{
								throw new Exception("Decryptor wrong");
							}
							binaryReader.BaseStream.Position = (long)((ulong)methodInfo2.MethodDataOffset);
							methodInfo2.Header = binaryReader.ReadBytes(4);
							int hInt = BitConverter.ToInt32(methodInfo2.Header, 0) >> 8;
							if (i == 0 && hInt != 305)
							{
								throw new Exception("Invalid hint!");
							}
							if (i == 1 && hInt != 15)
							{
								throw new Exception("Invalid hint!");
							}
							if (i == 2 && hInt != 317)
							{
								throw new Exception("Invalid hint!");
							}
							if (i == 0 && methodInfo2.Header[0] != 0)
							{
								throw new Exception("Invalid header!");
							}
							if (i == 1 && methodInfo2.Header[0] != 8)
							{
								throw new Exception("Invalid header!");
							}
							if (i == 2 && methodInfo2.Header[0] != 3)
							{
								throw new Exception("Invalid header!");
							}
							using (BinaryReader binaryReader2 = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
							{
								binaryReader2.BaseStream.Position = (long)hInt;
								int MethodBodySizeP = binaryReader2.ReadInt32() >> 8;
								int MethodBodySizeP2 = binaryReader2.ReadInt32() >> 8;
								if (i == 0 && (MethodBodySizeP != 104 || MethodBodySizeP2 != 104))
								{
									throw new Exception("Invalid method size!");
								}
								if (i == 2 && (MethodBodySizeP != 497 || MethodBodySizeP2 != 497))
								{
									throw new Exception("Invalid method size!");
								}
							}
						}
					}
					IL_076E:
					i++;
					continue;
					goto IL_076E;
				}
			}
		}

		// Token: 0x06000042 RID: 66 RVA: 0x00007C04 File Offset: 0x00006C04
		public override void ReadMethods()
		{
			if (base.IsApplicationMode())
			{
				throw new NotImplementedException();
			}
			if (this.version.StartsWith("3.9.0") || this.version.StartsWith("3.9.7") || this.version.StartsWith("4.0") || this.version.StartsWith("4.1") || this.version.StartsWith("4.3") || this.version.StartsWith("4.5.1") || this.version.StartsWith("4.8") || this.version.StartsWith("4.9"))
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
				this.DataStructure._MethodsOffsetTable = this.reader.ReadBytes((int)(this.DataStructure.MethodsCount * 4U));
				this.DataStructure._MethodsData = this.reader.ReadBytes((int)this.DataStructure.MethodsBufferLength);
				uint rva = (uint)this.module.Metadata.PEImage.ToRVA((FileOffset)this.reader.Position);
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = this.reader.ReadBytes((int)this.DataStructure.LEHSize);
				}
			}
			else
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.LocalsAndEHOffset);
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = this.reader.ReadBytes((int)this.DataStructure.LEHSize);
				}
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.MethodsDataOffset);
				this.DataStructure._MethodsOffsetTable = this.reader.ReadBytes((int)(this.DataStructure.MethodsCount * 4U));
				this.DataStructure._MethodsData = this.reader.ReadBytes((int)this.DataStructure.MethodsBufferLength);
			}
			if (base.IsEnterpriseEdition())
			{
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = new LZAri().Decode(this.DataStructure.LEH);
					base.DecryptPrevXor(this.DataStructure.LEH, this.KeyBuff);
				}
				this.DataStructure._MethodsData = new LZAri().Decode(this.DataStructure._MethodsData);
				if ((long)this.DataStructure._MethodsData.Length != (long)((ulong)this.UncompressedMethodsBufferLength))
				{
					throw new Exception("Invalid methods buffer!");
				}
				base.DecryptPrevXor(this.DataStructure._MethodsOffsetTable, this.KeyBuff);
				if (base.IsHVMTechnologyEnabled())
				{
					this.HvmTable = this.ReadHVMTable();
					base.XorSelf(this.DataStructure._MethodsOffsetTable, 0, 20);
				}
				this.InitializeEncryptionKeys();
			}
			else
			{
				if (this.DataStructure.LEHSize > 0U)
				{
					this.DataStructure.LEH = Compressor.Decompress(this.DataStructure.LEH);
					base.DecryptXor(this.DataStructure.LEH, this.KeyBuff);
				}
				base.DecryptXor(this.DataStructure._MethodsData, this.KeyBuff);
				base.DecryptXor(this.DataStructure._MethodsOffsetTable, this.KeyBuff);
			}
			uint[] MethodsOffsets = new uint[this.DataStructure.MethodsCount];
			Buffer.BlockCopy(this.DataStructure._MethodsOffsetTable, 0, MethodsOffsets, 0, this.DataStructure._MethodsOffsetTable.Length);
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(this.DataStructure._MethodsData)))
			{
				int i = 0;
				while (i < MethodsOffsets.Length)
				{
					if (MethodsOffsets[i] != 0U)
					{
						if (base.IsEnterpriseEdition())
						{
							if (MethodsOffsets[i] >> 28 == 2U)
							{
								uint rva = (MethodsOffsets[i] ^ this.DataStructure.ProtectionSettings) & 268435455U;
								this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
								if (this.reader.ReadByte() != 254)
								{
									throw new Exception("First byte missing!");
								}
								MethodsDecrypter.DecrypterBase.methodInfo methodInfo = new MethodsDecrypter.DecrypterBase.methodInfo
								{
									DecryptorType = this.reader.ReadByte(),
									MethodDataOffset = this.reader.ReadUInt32()
								};
								binaryReader.BaseStream.Position = (long)((ulong)methodInfo.MethodDataOffset);
								methodInfo.Header = binaryReader.ReadBytes(4);
								if (binaryReader.ReadUInt32() != 4294967295U)
								{
									throw new Exception("Invalid proxy method pointer!");
								}
								if (binaryReader.ReadUInt32() > 0U)
								{
									throw new Exception("Invalid proxy method pointer!");
								}
								byte[] data = binaryReader.ReadBytes(BitConverter.ToInt32(methodInfo.Header, 0) >> 8);
								base.DecryptXor(data, this.KeyBuff);
								base.DecryptPrevXor(data, this.KeyBuff);
								this.DecryptData2(data, (int)methodInfo.DecryptorType, false);
								Array.Resize<byte>(ref data, data.Length);
								if (BitConverter.ToUInt32(data, 0) != 656676094U && (BitConverter.ToUInt32(data, 0) & 255U) != 255U)
								{
									throw new Exception("Invalid dummy value!");
								}
								uint num = BitConverter.ToUInt32(data, 4);
								num = (num ^ ((this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings) & 16777215U)) & 16777215U;
								uint value = (uint)(i + 1);
								this.proxyMethods.Add(num, value);
								if (MethodsOffsets[(int)(num - 1U)] >> 28 == 4U || MethodsOffsets[(int)(num - 1U)] >> 28 == 12U)
								{
									rva = (MethodsOffsets[(int)(num - 1U)] ^ this.DataStructure.Encryption_Dword ^ this.value3) & 16777215U;
									this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva);
								}
							}
							else if (MethodsOffsets[i] >> 28 == 1U)
							{
								uint rva2 = (MethodsOffsets[i] ^ this.DataStructure.Encryption_Dword) & 268435455U;
								this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva2);
							}
							else
							{
								if (MethodsOffsets[i] >> 28 == 4U)
								{
									goto IL_0F53;
								}
								if (MethodsOffsets[i] >> 28 == 6U)
								{
									this.fakeMethods.Add(i);
									goto IL_0F53;
								}
								if (MethodsOffsets[i] >> 28 == 12U)
								{
									this.secureMethods.Add(i);
									goto IL_0F53;
								}
								if (MethodsOffsets[i] >> 24 == 248U)
								{
									this._anonymous_tokens.Add((uint)(i + 1), (uint)((ulong)(MethodsOffsets[i] & 16777215U) ^ (ulong)((long)(i + 1))));
									goto IL_0F53;
								}
								uint rva3 = (MethodsOffsets[i] ^ this.DataStructure.Encryption_Dword) & 268435455U;
								this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)rva3);
							}
						}
						else
						{
							if (MethodsOffsets[i] >> 24 == 248U)
							{
								this._anonymous_tokens.Add((uint)(i + 1), (uint)((ulong)(MethodsOffsets[i] & 16777215U) ^ (ulong)((long)(i + 1))));
								goto IL_0F53;
							}
							this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)MethodsOffsets[i]);
						}
						if (this.reader.ReadByte() != 254)
						{
							throw new Exception("First byte missing!");
						}
						MethodsDecrypter.DecrypterBase.methodInfo methodInfo2 = new MethodsDecrypter.DecrypterBase.methodInfo
						{
							DecryptorType = this.reader.ReadByte(),
							MDToken = new MDToken(i + 1),
							MethodDataOffset = this.reader.ReadUInt32(),
							Method = this.module.ResolveMethod((uint)(i + 1))
						};
						int MethodBodySize = 0;
						binaryReader.BaseStream.Position = (long)((ulong)methodInfo2.MethodDataOffset);
						methodInfo2.Header = binaryReader.ReadBytes(4);
						int hInt = BitConverter.ToInt32(methodInfo2.Header, 0) >> 8;
						methodInfo2.Method_Locals = new List<Local>();
						if (base.IsHVMTechnologyEnabled())
						{
							if ((methodInfo2.Header[0] & 8) == 0)
							{
								using (BinaryReader binaryReader2 = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
								{
									binaryReader2.BaseStream.Position = (long)hInt;
									short LocalsSize2 = 0;
									short EHSize2 = 0;
									if (this.version.StartsWith("3.9.5") || this.version.StartsWith("3.9.6") || this.version.StartsWith("4.1"))
									{
										MethodBodySize = binaryReader2.ReadInt32() >> 8;
										binaryReader2.ReadInt16();
										LocalsSize2 = binaryReader2.ReadInt16();
										EHSize2 = binaryReader2.ReadInt16();
										binaryReader2.ReadInt16();
									}
									else if (this.version.StartsWith("3.9.7") || this.version.StartsWith("4.0"))
									{
										LocalsSize2 = binaryReader2.ReadInt16();
										binaryReader2.ReadInt16();
										MethodBodySize = binaryReader2.ReadInt32() >> 8;
										binaryReader2.ReadInt16();
										EHSize2 = binaryReader2.ReadInt16();
									}
									else if (!this.version.StartsWith("4.3"))
									{
										if (!this.version.StartsWith("4.5.1"))
										{
											if (this.version.StartsWith("4.8") || this.version.StartsWith("4.9"))
											{
											}
										}
									}
									if (LocalsSize2 > 0)
									{
										using (BinaryReader localReader = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
										{
											for (int j = 0; j < (int)LocalsSize2; j++)
											{
												uint offset = binaryReader2.ReadUInt32();
												localReader.BaseStream.Position = (long)((ulong)(this.LEHLocalsOffset + (offset & 16777215U)));
												byte[] local = localReader.ReadBytes((int)((offset >> 24) * 4U));
												methodInfo2.Method_Locals.Add(new Local(SignatureReader.ReadTypeSig(this.module, local)));
											}
										}
									}
									methodInfo2.MethodEH = ((EHSize2 == 0) ? null : binaryReader2.ReadBytes((int)EHSize2));
									methodInfo2.HvmTokenTableOffset = binaryReader.ReadUInt32();
									methodInfo2.HvmTokenTableSize = binaryReader.ReadUInt32();
									methodInfo2.MethodData = binaryReader.ReadBytes(MethodBodySize);
									if (base.IsHVMTechnologyEnabled() && methodInfo2.HvmTokenTableOffset != 4294967295U && methodInfo2.HvmTokenTableSize > 0U)
									{
										methodInfo2.MethodHvmTokens = this.ParseHVMTableAtOffset(this.HvmTable, methodInfo2.HvmTokenTableOffset, methodInfo2.HvmTokenTableSize);
									}
								}
							}
							else
							{
								MethodBodySize = hInt;
								methodInfo2.HvmTokenTableOffset = binaryReader.ReadUInt32();
								methodInfo2.HvmTokenTableSize = binaryReader.ReadUInt32();
								methodInfo2.MethodData = binaryReader.ReadBytes(hInt);
								if (base.IsHVMTechnologyEnabled() && methodInfo2.HvmTokenTableOffset != 4294967295U && methodInfo2.HvmTokenTableSize > 0U)
								{
									methodInfo2.MethodHvmTokens = this.ParseHVMTableAtOffset(this.HvmTable, methodInfo2.HvmTokenTableOffset, methodInfo2.HvmTokenTableSize);
								}
							}
						}
						else if ((methodInfo2.Header[0] & 8) == 0)
						{
							using (BinaryReader binaryReader3 = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
							{
								binaryReader3.BaseStream.Position = (long)hInt;
								short LocalsSize2 = 0;
								short EHSize2 = 0;
								if (this.version.StartsWith("3.9.5") || this.version.StartsWith("3.9.6") || this.version.StartsWith("4.1"))
								{
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									short usless = binaryReader3.ReadInt16();
									LocalsSize2 = binaryReader3.ReadInt16();
									EHSize2 = binaryReader3.ReadInt16();
									short uselss2 = binaryReader3.ReadInt16();
								}
								else if (this.version.StartsWith("3.9.7") || this.version.StartsWith("4.0"))
								{
									int crap = binaryReader3.ReadInt32();
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									LocalsSize2 = binaryReader3.ReadInt16();
									EHSize2 = binaryReader3.ReadInt16();
								}
								else if (this.version.StartsWith("4.3"))
								{
									int crap = binaryReader3.ReadInt32();
									EHSize2 = binaryReader3.ReadInt16();
									LocalsSize2 = binaryReader3.ReadInt16();
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
								}
								else if (this.version.StartsWith("4.5.1"))
								{
									EHSize2 = binaryReader3.ReadInt16();
									short value2 = binaryReader3.ReadInt16();
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									LocalsSize2 = binaryReader3.ReadInt16();
									binaryReader3.ReadInt16();
								}
								else if (this.version.StartsWith("4.8") || this.version.StartsWith("4.9"))
								{
									MethodBodySize = binaryReader3.ReadInt32() >> 8;
									short ehClauseCount = binaryReader3.ReadInt16(); // number of EH clauses
									binaryReader3.ReadInt16();                       // unused (always 0)
									EHSize2 = binaryReader3.ReadInt16();             // total EH byte size (incl. 4-byte header)
									LocalsSize2 = binaryReader3.ReadInt16();         // LocalsSig byte size
								}
								methodInfo2.MethodData = binaryReader.ReadBytes(MethodBodySize);
								IList<TypeSig> locals = ((LocalSig)SignatureReader.ReadSig(this.module, binaryReader3.ReadBytes((int)LocalsSize2))).GetLocals();
								for (int k = 0; k < locals.Count; k++)
								{
									methodInfo2.Method_Locals.Add(new Local(locals[k]));
								}
								methodInfo2.MethodEH = ((EHSize2 == 0) ? null : binaryReader3.ReadBytes((int)EHSize2));
							}
						}
						else
						{
							MethodBodySize = hInt;
							methodInfo2.MethodData = binaryReader.ReadBytes(hInt);
						}
						binaryReader.BaseStream.Position = (long)((ulong)(methodInfo2.MethodDataOffset + 4U) + (ulong)(base.IsHVMTechnologyEnabled() ? 8L : 0L));
						methodInfo2.MethodData = binaryReader.ReadBytes(Convert.ToInt32((long)(MethodBodySize + 7) & unchecked((long)(ulong)(-8))));
						this.DecryptData2(methodInfo2.MethodData, (int)methodInfo2.DecryptorType, true);
						Array.Resize<byte>(ref methodInfo2.MethodData, MethodBodySize);
						this.methodInfos.Add((uint)(i + 1), methodInfo2);
					}
					IL_0F53:
					i++;
					continue;
					goto IL_0F53;
				}
			}
		}

		// Token: 0x06000043 RID: 67 RVA: 0x00008BF4 File Offset: 0x00007BF4
		private void DecryptData2(byte[] data, int decryptorId, bool hvm_xor)
		{
			if (decryptorId == 0)
			{
				bool flag2 = base.IsHVMTechnologyEnabled() && hvm_xor;
				if (flag2)
				{
					base.DecryptNextXor(data, this.KeyBuff);
				}
				base.DecryptXor(data, this.KeyBuff);
			}
			else if (decryptorId == 1)
			{
				bool flag3 = base.IsHVMTechnologyEnabled() && hvm_xor;
				if (flag3)
				{
					base.DecryptNextXor(data, this.KeyBuff);
				}
				byte prev = this.KeyBuff[this.KeyBuff.Length - 1];
				for (int i = 0; i < data.Length; i++)
				{
					byte next = (byte)(data[i] ^ this.KeyBuff[i % this.KeyBuff.Length] ^ prev);
					prev = data[i];
					data[i] = next;
				}
			}
			else if (decryptorId == 8)
			{
				bool flag4 = base.IsHVMTechnologyEnabled() && hvm_xor;
				if (flag4)
				{
					base.DecryptNextXor(data, this.KeyBuff);
				}
				int buff_counter = 0;
				int buff_index = 0;
				bool flag5 = data.Length >> 3 > 0;
				if (flag5)
				{
					uint[] buff = new uint[data.Length / 4];
					Buffer.BlockCopy(data, 0, buff, 0, data.Length);
					while (buff_counter < data.Length >> 3)
					{
						uint uVar7 = this.DataStructure.Encryption_Dword * 8U;
						int cnt = 7;
						uint uVar8 = buff[buff_index];
						uint uVar9 = buff[buff_index + 1] - ((((uVar8 >> 5) ^ (uVar8 << 4)) + uVar8) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar7 >> 11) & 3U) * 4U)) + uVar7));
						uVar7 -= this.DataStructure.Encryption_Dword;
						while (cnt != 0)
						{
							uVar8 -= (((uVar9 >> 5) ^ (uVar9 * 16U)) + uVar9) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((uVar7 & 3U) * 4U)) + uVar7);
							uVar9 -= (((uVar8 >> 5) ^ (uVar8 * 16U)) + uVar8) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar7 >> 11) & 3U) * 4U)) + uVar7);
							uVar7 -= this.DataStructure.Encryption_Dword;
							cnt--;
						}
						buff[buff_index] = (uVar8 - ((((uVar9 >> 5) ^ (uVar9 * 16U)) + uVar9) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((uVar7 & 3U) * 4U)))) ^ this.DataStructure.Encryption_Dword;
						buff[buff_index + 1] = uVar9;
						buff_counter++;
						buff_index += 2;
					}
					Buffer.BlockCopy(buff, 0, data, 0, data.Length);
				}
			}
			else
			{
				bool flag6 = decryptorId == 6;
				if (flag6)
				{
					bool flag7 = base.IsHVMTechnologyEnabled() && hvm_xor;
					if (flag7)
					{
						base.DecryptNextXor(data, this.KeyBuff);
					}
					int buff_counter2 = 0;
					int buff_index2 = 0;
					bool flag8 = data.Length >> 3 > 0;
					if (flag8)
					{
						uint[] buff2 = new uint[data.Length / 4];
						Buffer.BlockCopy(data, 0, buff2, 0, data.Length);
						while (buff_counter2 < data.Length >> 3)
						{
							uint uVar10 = this.DataStructure.Encryption_Dword * 6U;
							for (int cnt2 = 6; cnt2 != 0; cnt2--)
							{
								uint uVar11 = (uVar10 >> 2) & 3U;
								uint uVar12 = buff2[buff_index2];
								uint y = (((uVar12 << 4) ^ (uVar12 >> 3)) + ((uVar12 >> 5) ^ (uVar12 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)((uVar11 ^ 1U) * 4U)) ^ uVar12) + (uVar12 ^ uVar10));
								buff2[buff_index2 + 1] = buff2[buff_index2 + 1] - y;
								uVar12 = buff2[buff_index2 + 1];
								y = (((uVar12 << 4) ^ (uVar12 >> 3)) + ((uVar12 >> 5) ^ (uVar12 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(uVar11 * 4U)) ^ uVar12) + (uVar12 ^ uVar10));
								buff2[buff_index2] -= y;
								uVar10 -= this.DataStructure.Encryption_Dword;
							}
							buff_counter2++;
							buff_index2 += 2;
						}
						Buffer.BlockCopy(buff2, 0, data, 0, data.Length);
					}
				}
				else
				{
					bool flag9 = decryptorId == 10;
					if (flag9)
					{
						bool flag10 = base.IsHVMTechnologyEnabled() && hvm_xor;
						if (flag10)
						{
							base.DecryptNextXor(data, this.KeyBuff);
						}
						int buff_counter3 = 0;
						int buff_index3 = 0;
						bool flag11 = data.Length >> 3 > 0;
						if (flag11)
						{
							uint[] buff3 = new uint[data.Length / 4];
							Buffer.BlockCopy(data, 0, buff3, 0, data.Length);
							while (buff_counter3 < data.Length >> 3)
							{
								buff3[buff_index3] ^= this.DataStructure.Encryption_Dword;
								uint uVar13 = this.DataStructure.Encryption_Dword * 8U;
								for (int cnt3 = 8; cnt3 != 0; cnt3--)
								{
									uint uVar14 = (uVar13 >> 2) & 3U;
									uint uVar15 = buff3[buff_index3];
									uint y2 = (((uVar15 << 4) ^ (uVar15 >> 3)) + ((uVar15 >> 5) ^ (uVar15 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)(uVar14 ^ 1U) + (ulong)((long)buff_counter3)) * 4UL % (ulong)((long)this.KeyBuff.Length))) ^ uVar15) + (uVar15 ^ uVar13));
									buff3[buff_index3 + 1] = buff3[buff_index3 + 1] - y2;
									uVar15 = buff3[buff_index3 + 1];
									y2 = (((uVar15 << 4) ^ (uVar15 >> 3)) + ((uVar15 >> 5) ^ (uVar15 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)uVar14 + (ulong)((long)buff_counter3)) * 4UL) % this.KeyBuff.Length) ^ uVar15) + (uVar15 ^ uVar13));
									buff3[buff_index3] -= y2;
									uVar13 -= this.DataStructure.Encryption_Dword;
								}
								buff_counter3++;
								buff_index3 += 2;
							}
							Buffer.BlockCopy(buff3, 0, data, 0, data.Length);
						}
					}
					else
					{
						bool flag12 = decryptorId == 14;
						if (flag12)
						{
							bool flag13 = base.IsHVMTechnologyEnabled() && hvm_xor;
							if (flag13)
							{
								base.DecryptNextXor(data, this.KeyBuff);
							}
							int buff_counter4 = 0;
							int buff_index4 = 0;
							bool flag14 = data.Length >> 3 > 0;
							if (flag14)
							{
								uint[] buff4 = new uint[data.Length / 4];
								Buffer.BlockCopy(data, 0, buff4, 0, data.Length);
								while (buff_counter4 < data.Length >> 3)
								{
									uint uVar16 = this.DataStructure.Encryption_Dword * 9U;
									int cnt4 = 8;
									uint uVar17 = buff4[buff_index4];
									uint uVar18 = (buff4[buff_index4 + 1] ^ this.DataStructure.Encryption_Dword) - ((((uVar17 >> 5) ^ (uVar17 << 4)) + uVar17) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar16 >> 11) & 3U) * 4U)) + uVar16));
									uVar16 -= this.DataStructure.Encryption_Dword;
									while (cnt4 != 0)
									{
										uVar17 -= (((uVar18 >> 5) ^ (uVar18 * 16U)) + uVar18) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((uVar16 & 3U) * 4U)) + uVar16);
										uVar18 -= (((uVar17 >> 5) ^ (uVar17 * 16U)) + uVar17) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((uVar16 >> 11) & 3U) * 4U)) + uVar16);
										uVar16 -= this.DataStructure.Encryption_Dword;
										cnt4--;
									}
									buff4[buff_index4] = uVar17 - ((((uVar18 >> 5) ^ (uVar18 * 16U)) + uVar18) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((uVar16 & 3U) * 4U)));
									buff4[buff_index4 + 1] = uVar18;
									buff_counter4++;
									buff_index4 += 2;
								}
								Buffer.BlockCopy(buff4, 0, data, 0, data.Length);
							}
						}
						else
						{
							bool flag15 = decryptorId == 2;
							if (flag15)
							{
								bool flag16 = base.IsHVMTechnologyEnabled() && hvm_xor;
								if (flag16)
								{
									base.DecryptNextXor(data, this.KeyBuff);
								}
								byte[] blob = new byte[256];
								int uVar19 = 0;
								int index = 0;
								for (int j = 0; j < blob.Length; j++)
								{
									if (j % 4 == 0)
									{
										index = 0;
									}
									blob[j] = (byte)((int)BitConverter.GetBytes(this.DataStructure.Encryption_Dword)[index] ^ uVar19);
									uVar19++;
									index++;
								}
								byte[] blob2 = new byte[256];
								uVar19 = 0;
								index = 0;
								for (int k = 0; k < blob2.Length; k++)
								{
									if (k % 16 == 0)
									{
										index = 0;
									}
									blob2[k] = (byte)(this.KeyBuff[index] ^ (byte)(uVar19 >> 4));
									byte[] array = blob;
									int num = k;
									byte[] array2 = array;
									int num3 = num;
									array2[num3] ^= blob2[k];
									uVar19++;
									index++;
								}
								int tmp = 0;
								for (int l = 0; l < blob.Length; l++)
								{
									tmp = tmp + (int)blob[l] + (int)blob2[l];
									byte tmp2 = blob[l];
									blob[l] = blob[tmp & 255];
									blob[tmp & 255] = tmp2;
								}
								int start = 1;
								tmp = 0;
								for (int m = 0; m < data.Length; m++)
								{
									byte tmp3 = blob[start & 255];
									tmp = (tmp + (int)tmp3) & 255;
									byte tmp4 = blob[tmp];
									blob[start & 255] = tmp4;
									blob[tmp] = tmp3;
									int num2 = m;
									int num4 = num2;
									data[num4] ^= blob[(int)((tmp3 + tmp4) & byte.MaxValue)];
									start++;
								}
							}
							else
							{
								bool flag17 = decryptorId == 12;
								if (flag17)
								{
									bool flag18 = base.IsHVMTechnologyEnabled() && hvm_xor;
									if (flag18)
									{
										base.DecryptNextXor(data, this.KeyBuff);
									}
									bool flag19 = data.Length >> 3 > 0;
									if (flag19)
									{
										uint w = this.DataStructure.Encryption_Dword ^ 2656670661U;
										uint enc_w = 8U * w;
										uint init_w = enc_w;
										uint[] buff5 = new uint[data.Length / 4];
										Buffer.BlockCopy(data, 0, buff5, 0, data.Length);
										for (int n = 0; n < buff5.Length; n += 2)
										{
											uint dw2 = buff5[n] ^ this.DataStructure.Encryption_Dword;
											uint dw3 = buff5[n + 1] ^ dw2;
											while (enc_w > 0U)
											{
												dw3 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((enc_w >> 11) & 3U) * 4U)) + ((dw2 << 5) ^ (dw2 >> 7)) + (dw2 ^ enc_w);
												enc_w -= w;
												dw2 -= BitConverter.ToUInt32(this.KeyBuff, (int)((enc_w & 3U) * 4U)) + ((32U * dw3) ^ (dw3 >> 7)) + (dw3 ^ enc_w);
											}
											enc_w = init_w;
											buff5[n] = dw2;
											buff5[n + 1] = dw3;
										}
										Buffer.BlockCopy(buff5, 0, data, 0, data.Length);
									}
								}
								else
								{
									bool flag20 = decryptorId == 4;
									if (flag20)
									{
										bool flag21 = base.IsHVMTechnologyEnabled() && hvm_xor;
										if (flag21)
										{
											base.DecryptNextXor(data, this.KeyBuff);
										}
										bool flag22 = data.Length >> 3 > 0;
										if (flag22)
										{
											uint w2 = this.DataStructure.Encryption_Dword ^ 2656670661U;
											uint enc_w2 = 8U * w2;
											uint init_w2 = enc_w2;
											uint[] buff6 = new uint[data.Length / 4];
											Buffer.BlockCopy(data, 0, buff6, 0, data.Length);
											for (int j2 = 0; j2 < buff6.Length; j2 += 2)
											{
												uint dw4 = buff6[j2 + 1];
												uint dw5 = buff6[j2] ^ dw4;
												while (enc_w2 > 0U)
												{
													dw4 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((enc_w2 >> 11) & 3U) * 4U)) + ((8U * dw5) ^ (dw5 >> 7)) + (dw5 ^ enc_w2);
													enc_w2 -= w2;
													dw5 -= BitConverter.ToUInt32(this.KeyBuff, (int)((enc_w2 & 3U) * 4U)) + ((8U * dw4) ^ (dw4 >> 7)) + (dw4 ^ enc_w2);
												}
												enc_w2 = init_w2;
												buff6[j2] = dw5;
												buff6[j2 + 1] = dw4;
											}
											Buffer.BlockCopy(buff6, 0, data, 0, data.Length);
										}
									}
									else
									{
										bool flag23 = decryptorId == 11;
										if (flag23)
										{
											bool flag24 = base.IsHVMTechnologyEnabled() && hvm_xor;
											if (flag24)
											{
												base.DecryptNextXor(data, this.KeyBuff);
											}
											int type = 2;
											new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword).Process(data, data.Length, type);
										}
										else
										{
											bool flag25 = decryptorId == 9;
											if (flag25)
											{
												bool flag26 = base.IsHVMTechnologyEnabled() && hvm_xor;
												if (flag26)
												{
													base.DecryptNextXor(data, this.KeyBuff);
												}
												int type2 = 1;
												new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword).Process(data, data.Length, type2);
											}
											else
											{
												if (decryptorId != 13)
												{
													throw new NotImplementedException();
												}
												bool flag27 = base.IsHVMTechnologyEnabled() && hvm_xor;
												if (flag27)
												{
													base.DecryptNextXor(data, this.KeyBuff);
												}
												int type3 = 0;
												new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword).Process(data, data.Length, type3);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Token: 0x06000044 RID: 68 RVA: 0x000099B0 File Offset: 0x000089B0
		private void DecryptData(byte[] data, int decryptorId, bool hvm_xor)
		{
			switch (decryptorId)
			{
			case 0:
				base.DecryptXor(data, this.KeyBuff);
				return;
			case 1:
			{
				byte b3 = this.KeyBuff[this.KeyBuff.Length - 1];
				for (int i = 0; i < data.Length; i++)
				{
					byte b4 = (byte)(data[i] ^ this.KeyBuff[i % this.KeyBuff.Length] ^ b3);
					b3 = data[i];
					data[i] = b4;
				}
				return;
			}
			case 2:
			{
				byte[] array8 = new byte[256];
				int num39 = 0;
				int num40 = 0;
				for (int j = 0; j < array8.Length; j++)
				{
					if (j % 4 == 0)
					{
						num40 = 0;
					}
					array8[j] = (byte)((int)BitConverter.GetBytes(this.DataStructure.Encryption_Dword)[num40] ^ num39);
					num39++;
					num40++;
				}
				byte[] array9 = new byte[256];
				num39 = 0;
				num40 = 0;
				for (int k = 0; k < array9.Length; k++)
				{
					if (k % 16 == 0)
					{
						num40 = 0;
					}
					array9[k] = this.KeyBuff[num40];
					byte[] array17 = array8;
					int num83 = k;
					array17[num83] ^= array9[k];
					num39++;
					num40++;
				}
				int num41 = 0;
				for (int num42 = 0; num42 < array8.Length; num42++)
				{
					num41 = num41 + (int)array8[num42] + (int)array9[num42];
					byte b5 = array8[num42];
					array8[num42] = array8[num41 & 255];
					array8[num41 & 255] = b5;
				}
				int num43 = 1;
				num41 = 0;
				for (int num44 = 0; num44 < data.Length; num44++)
				{
					byte b6 = array8[num43 & 255];
					num41 = (num41 + (int)b6) & 255;
					byte b7 = (array8[num43 & 255] = array8[num41]);
					array8[num41] = b6;
					int num84 = num44;
					data[num84] ^= array8[(int)((b6 + b7) & byte.MaxValue)];
					num43++;
				}
				return;
			}
			case 4:
			{
				int num45 = 0;
				int num46 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array10 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array10, 0, data.Length);
				while (num45 < data.Length >> 3)
				{
					uint num47 = this.DataStructure.Encryption_Dword * 4U;
					int num48 = 3;
					uint num49 = array10[num46];
					uint num50 = array10[num46 + 1] - ((((num49 >> 5) ^ (num49 << 4)) + num49) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num47 >> 11) & 3U) * 4U)) + num47));
					num47 -= this.DataStructure.Encryption_Dword;
					while (num48 != 0)
					{
						num49 -= (((num50 >> 5) ^ (num50 * 16U)) + num50) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((num47 & 3U) * 4U)) + num47);
						num50 -= (((num49 >> 5) ^ (num49 * 16U)) + num49) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num47 >> 11) & 3U) * 4U)) + num47);
						num47 -= this.DataStructure.Encryption_Dword;
						num48--;
					}
					array10[num46] = num49 - ((((num50 >> 5) ^ (num50 * 16U)) + num50) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((num47 & 3U) * 4U)));
					array10[num46 + 1] = num50 ^ this.DataStructure.Encryption_Dword;
					num45++;
					num46 += 2;
				}
				Buffer.BlockCopy(array10, 0, data, 0, data.Length);
				return;
			}
			case 5:
			{
				int num51 = 0;
				int num52 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array11 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array11, 0, data.Length);
				while (num51 < data.Length >> 3)
				{
					uint num53 = this.DataStructure.Encryption_Dword * 3U;
					for (int num54 = 3; num54 != 0; num54--)
					{
						uint num55 = (num53 >> 2) & 3U;
						uint num56 = array11[num52];
						uint num57 = (((num56 << 4) ^ (num56 >> 3)) + ((num56 >> 5) ^ (num56 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)((num55 ^ 1U) * 4U)) ^ num56) + (num56 ^ num53));
						array11[num52 + 1] = array11[num52 + 1] - num57;
						num56 = array11[num52 + 1];
						num57 = (((num56 << 4) ^ (num56 >> 3)) + ((num56 >> 5) ^ (num56 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(num55 * 4U)) ^ num56) + (num56 ^ num53));
						array11[num52] -= num57;
						num53 -= this.DataStructure.Encryption_Dword;
					}
					num51++;
					num52 += 2;
				}
				Buffer.BlockCopy(array11, 0, data, 0, data.Length);
				return;
			}
			case 6:
			{
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint num58 = this.DataStructure.Encryption_Dword ^ 2656670661U;
				uint num59 = 8U * num58;
				uint num60 = num59;
				uint[] array12 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array12, 0, data.Length);
				for (int l = 0; l < array12.Length; l += 2)
				{
					uint num61 = array12[l];
					uint num62 = array12[l + 1] ^ num61;
					while (num59 != 0U)
					{
						num62 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((num59 >> 11) & 3U) * 4U)) + ((8U * num61) ^ (num61 >> 7)) + (num61 ^ num59);
						num59 -= num58;
						num61 -= BitConverter.ToUInt32(this.KeyBuff, (int)((num59 & 3U) * 4U)) + ((8U * num62) ^ (num62 >> 7)) + (num62 ^ num59);
					}
					num59 = num60;
					array12[l] = num61;
					array12[l + 1] = num62;
				}
				Buffer.BlockCopy(array12, 0, data, 0, data.Length);
				return;
			}
			case 9:
			{
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint num63 = this.DataStructure.Encryption_Dword ^ 2656670661U;
				uint num64 = 8U * num63;
				uint num65 = num64;
				uint[] array13 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array13, 0, data.Length);
				for (int m = 0; m < array13.Length; m += 2)
				{
					uint num66 = array13[m] ^ this.DataStructure.Encryption_Dword;
					uint num67 = array13[m + 1];
					while (num64 != 0U)
					{
						num67 -= BitConverter.ToUInt32(this.KeyBuff, (int)(((num64 >> 11) & 3U) * 4U)) + ((num66 << 5) ^ (num66 >> 7)) + (num66 ^ num64);
						num64 -= num63;
						num66 -= BitConverter.ToUInt32(this.KeyBuff, (int)((num64 & 3U) * 4U)) + ((32U * num67) ^ (num67 >> 7)) + (num67 ^ num64);
					}
					num64 = num65;
					array13[m] = num66;
					array13[m + 1] = num67;
				}
				Buffer.BlockCopy(array13, 0, data, 0, data.Length);
				return;
			}
			case 10:
			{
				int type3 = 2;
				this.blowfishInstance.Process(data, data.Length, type3);
				return;
			}
			case 11:
			{
				int type4 = 0;
				this.blowfishInstance.Process(data, data.Length, type4);
				return;
			}
			case 12:
			{
				int type5 = 1;
				this.blowfishInstance.Process(data, data.Length, type5);
				return;
			}
			case 13:
			{
				int num68 = 0;
				int num69 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array14 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array14, 0, data.Length);
				while (num68 < data.Length >> 3)
				{
					uint num70 = this.DataStructure.Encryption_Dword * 6U;
					int num71 = 5;
					uint num72 = array14[num69] ^ array14[num69 + 1];
					uint num73 = array14[num69 + 1] - ((((num72 >> 5) ^ (num72 << 4)) + num72) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num70 >> 11) & 3U) * 4U)) + num70));
					num70 -= this.DataStructure.Encryption_Dword;
					while (num71 != 0)
					{
						num72 -= (((num73 >> 5) ^ (num73 * 16U)) + num73) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)((num70 & 3U) * 4U)) + num70);
						num73 -= (((num72 >> 5) ^ (num72 * 16U)) + num72) ^ (BitConverter.ToUInt32(this.KeyBuff, (int)(((num70 >> 11) & 3U) * 4U)) + num70);
						num70 -= this.DataStructure.Encryption_Dword;
						num71--;
					}
					array14[num69] = num72 - ((((num73 >> 5) ^ (num73 * 16U)) + num73) ^ BitConverter.ToUInt32(this.KeyBuff, (int)((num70 & 3U) * 4U)));
					array14[num69 + 1] = num73;
					num68++;
					num69 += 2;
				}
				Buffer.BlockCopy(array14, 0, data, 0, data.Length);
				return;
			}
			case 14:
			{
				int num74 = 0;
				int num75 = 0;
				if (data.Length >> 3 <= 0)
				{
					return;
				}
				uint[] array15 = new uint[data.Length / 4];
				Buffer.BlockCopy(data, 0, array15, 0, data.Length);
				while (num74 < data.Length >> 3)
				{
					array15[num75] ^= this.DataStructure.Encryption_Dword;
					uint num76 = this.DataStructure.Encryption_Dword * 6U;
					for (int num77 = 6; num77 != 0; num77--)
					{
						uint num78 = (num76 >> 2) & 3U;
						uint num79 = array15[num75];
						uint num80 = (((num79 << 4) ^ (num79 >> 3)) + ((num79 >> 5) ^ (num79 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)(num78 ^ 1U) + (ulong)((long)num74)) * 4UL % (ulong)((long)this.KeyBuff.Length))) ^ num79) + (num79 ^ num76));
						array15[num75 + 1] = array15[num75 + 1] - num80;
						num79 = array15[num75 + 1];
						num80 = (((num79 << 4) ^ (num79 >> 3)) + ((num79 >> 5) ^ (num79 * 4U))) ^ ((BitConverter.ToUInt32(this.KeyBuff, (int)(((ulong)num78 + (ulong)((long)num74)) * 4UL) % this.KeyBuff.Length) ^ num79) + (num79 ^ num76));
						array15[num75] -= num80;
						num76 -= this.DataStructure.Encryption_Dword;
					}
					num74++;
					num75 += 2;
				}
				Buffer.BlockCopy(array15, 0, data, 0, data.Length);
				return;
			}
			case 15:
			{
				byte[] array16 = new byte[256];
				Buffer.BlockCopy(this.algoKey, 0, array16, 0, this.algoKey.Length);
				int num81 = 0;
				int num82 = 0;
				for (int n = 0; n < data.Length; n++)
				{
					num81++;
					byte b8 = array16[num81 & 255];
					num82 = (num82 + (int)b8) & 255;
					byte b9 = (array16[num81 & 255] = array16[num82 & 255]);
					array16[num82 & 255] = b8;
					data[n] ^= array16[(int)((b9 + b8) & byte.MaxValue)];
				}
				return;
			}
			}
			throw new NotImplementedException();
		}

		// Token: 0x06000045 RID: 69 RVA: 0x0000A514 File Offset: 0x00009514
		public void InitializeEncryptionKeys()
		{
			this.blowfishInstance = new Blowfish(this.KeyBuff, this.DataStructure.Encryption_Dword ^ this.DataStructure.ProtectionSettings);
			byte[] array = new byte[this.KeyBuff.Length + 4];
			Buffer.BlockCopy(this.KeyBuff, 0, array, 0, this.KeyBuff.Length);
			Buffer.BlockCopy(BitConverter.GetBytes(this.DataStructure.Encryption_Dword), 0, array, array.Length - 4, 4);
			this.algoKey = this.InitializeEncryptionKey(array);
		}

		// Token: 0x06000046 RID: 70 RVA: 0x0000A59C File Offset: 0x0000959C
		public byte[] InitializeEncryptionKey(byte[] hash_key)
		{
			byte[] array = new byte[256];
			byte[] array2 = new byte[256];
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = (byte)i;
				array2[i] = hash_key[i % hash_key.Length];
			}
			int num = 0;
			for (int j = 0; j < array.Length; j++)
			{
				int num2 = ((int)array2[j] + num + (int)array[j] + 1) & 255;
				int num3 = (int)array[num2];
				int num4 = (int)array[j];
				array[j] = (byte)num3;
				array[num2] = (byte)num4;
				num = num2;
			}
			return array;
		}

		// Token: 0x06000047 RID: 71 RVA: 0x0000A63C File Offset: 0x0000963C
		private byte[] ReadHVMTable()
		{
			byte[] result;
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(this.DataStructure.LEH)))
			{
				binaryReader.BaseStream.Position = (long)((ulong)this.HvmTokenTableOffset);
				result = binaryReader.ReadBytes((int)this.HvmTokenTableSize);
			}
			return result;
		}

		// Token: 0x06000048 RID: 72 RVA: 0x0000A6AC File Offset: 0x000096AC
		private uint[] ParseHVMTableAtOffset(byte[] hvm_table, uint offset, uint size)
		{
			List<uint> list = new List<uint>();
			int num = 0;
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(hvm_table)))
			{
				binaryReader.BaseStream.Position = (long)((ulong)(offset >> 1));
				while ((long)num != (long)((ulong)size))
				{
					uint num2 = binaryReader.ReadUInt32();
					if ((num2 >> 28) - 3U < 5U)
					{
						if ((offset & 1U) == 0U)
						{
							list.Add(num2);
							num++;
						}
						else if ((offset & 1U) == 1U)
						{
							list.Add(num2);
							binaryReader.BaseStream.Position += 4L;
							num += 2;
						}
					}
					else
					{
						list.Add(num2);
						num++;
					}
				}
			}
			return list.ToArray();
		}

		// Token: 0x06000049 RID: 73 RVA: 0x0000A7A8 File Offset: 0x000097A8
		public override uint DecryptHVMToken(uint hvmToken, int hvm_counter, MethodsDecrypter.DecrypterBase.methodInfo mi)
		{
			uint result;
			if ((hvmToken & 4278190080U) == 1879048192U)
			{
				result = hvmToken;
			}
			else
			{
				int num = (int)(hvmToken & 1048575U);
				hvmToken = mi.MethodHvmTokens[hvm_counter - 1];
				byte[] bytes = BitConverter.GetBytes(hvmToken);
				byte[] array = new byte[bytes.Length];
				bytes.CopyTo(array, 0);
				bytes[0] = array[2];
				bytes[1] = array[0];
				bytes[2] = array[1];
				hvmToken = BitConverter.ToUInt32(bytes, 0);
				uint num2;
				if (base.IsCompatibilityModeEnabled())
				{
					num2 = (uint)((ulong)(this.DataStructure.ProtectionSettings ^ ((this.DataStructure.Encryption_Dword ^ (this.DataStructure.Encryption_Dword >> 8)) & 268435455U) ^ hvmToken) ^ (ulong)((long)num));
				}
				else
				{
					num2 = (uint)((ulong)(this.DataStructure.ProtectionSettings ^ (this.DataStructure.Encryption_Dword & 268435455U) ^ hvmToken) ^ (ulong)((long)num));
				}
				if (base.IsApplicationMode())
				{
					num2 ^= this.DataStructure.Encryption_Dword >> 16;
				}
				uint num3 = DNGDecrypter.tokenBases[(int)(num2 >> 28)] | ((num2 >> 6) & 4194303U);
				result = num3;
			}
			return result;
		}

		// Token: 0x04000045 RID: 69
		public int StructSize = 0;

		// Token: 0x04000046 RID: 70
		private string version;

		// Token: 0x04000047 RID: 71
		public static uint[] ivalues;

		// Token: 0x04000048 RID: 72
		private uint value1;

		// Token: 0x04000049 RID: 73
		private uint value2;

		// Token: 0x0400004A RID: 74
		private uint value3;

		// Token: 0x0400004B RID: 75
		private uint valueN4;

		// Token: 0x0400004C RID: 76
		private uint valueN5;

		// Token: 0x0400004D RID: 77
		private Blowfish blowfishInstance;

		// Token: 0x0400004E RID: 78
		private byte[] algoKey;

		// Token: 0x0400004F RID: 79
		private uint UncompressedMethodsBufferLength;

		// Token: 0x04000050 RID: 80
		private uint LEHLocalsOffset;

		// Token: 0x04000051 RID: 81
		private uint HvmTokenTableOffset;

		// Token: 0x04000052 RID: 82
		private uint HvmTokenTableSize;

		// Token: 0x04000053 RID: 83
		private byte[] HvmTable;

		// Token: 0x04000054 RID: 84
		public static uint[] tokenBases = new uint[] { 452984832U, 16777216U, 33554432U, 167772160U, 67108864U, 167772160U, 100663296U, 721420288U, 1879048192U, 285212672U };
	}
}
