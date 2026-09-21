using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;
using dnlib.PE;

namespace DNGuard_Unpacker
{
	// Token: 0x02000007 RID: 7
	public class MethodsDecrypter
	{
		// Token: 0x17000002 RID: 2
		// (get) Token: 0x06000018 RID: 24 RVA: 0x00003BE8 File Offset: 0x00002BE8
		public bool Detected
		{
			get
			{
				return this.foundRtType || this.DNGRtType != null;
			}
		}

		// Token: 0x17000003 RID: 3
		// (get) Token: 0x06000019 RID: 25 RVA: 0x00003C14 File Offset: 0x00002C14
		public MethodDef InitializeMethod
		{
			get
			{
				return this.initializeMethod;
			}
		}

		// Token: 0x17000004 RID: 4
		// (get) Token: 0x0600001A RID: 26 RVA: 0x00003C2C File Offset: 0x00002C2C
		public TypeDef RTType
		{
			get
			{
				return this.DNGRtType;
			}
		}

		// Token: 0x17000005 RID: 5
		// (get) Token: 0x0600001B RID: 27 RVA: 0x00003C44 File Offset: 0x00002C44
		public string Version
		{
			get
			{
				return this.version;
			}
		}

		// Token: 0x0600001C RID: 28 RVA: 0x00003C5C File Offset: 0x00002C5C
		public MethodsDecrypter(ModuleDefMD module)
		{
			this.module = module;
		}

		// Token: 0x0600001D RID: 29 RVA: 0x00003C70 File Offset: 0x00002C70
		public void DecryptInternal(ref byte[] fileData)
		{
			if (this.decrypter != null)
			{
				this.decrypter.DecryptInternal(ref fileData);
			}
		}

		// Token: 0x0600001E RID: 30 RVA: 0x00003C9C File Offset: 0x00002C9C
		public void Decrypt()
		{
			if (this.decrypter != null)
			{
				this.decrypter.ReadMethods();
				this.decrypter.RestoreMethods();
			}
		}

		// Token: 0x0600001F RID: 31 RVA: 0x00003CD4 File Offset: 0x00002CD4
		public void Find()
		{
			string typeName = "NETShieldRT";
			foreach (TypeDef typeDef in this.module.GetTypes())
			{
				if (typeDef.FullName.Contains("ZYXDNGuarder"))
				{
					this.DNGRtType = typeDef;
					foreach (MethodDef method in typeDef.Methods)
					{
						if (method.Name == "Startup" || method.Name == "Execute")
						{
							this.initializeMethod = method;
							this.foundRtType = true;
						}
						bool flag2 = method.FullName.Contains("ZYXDNGuarder::CheckRuntime()") || method.FullName.Contains("ZYXDNGuarder::CheckRuntime(System.Int32)");
						if (flag2)
						{
							bool hasImplMap = method.HasImplMap;
							if (hasImplMap)
							{
								string NativeModuleName = method.ImplMap.Module.Name;
								string directoryName;
								if (this.module.Location == null || this.module.Location == "")
								{
									directoryName = Path.GetDirectoryName(Program.path);
								}
								else
								{
									directoryName = Path.GetDirectoryName(this.module.Location);
								}
								if (directoryName == null)
								{
									throw new InvalidOperationException("Invalid path");
								}
								MethodsDecrypter.NativeModulePath32 = Path.Combine(directoryName, NativeModuleName);
								this.foundRtType = true;
							}
						}
					}
				}
				if (typeDef.FullName.Contains(typeName))
				{
					this.DNGRtType = typeDef;
					foreach (MethodDef methodDef in typeDef.Methods)
					{
						if (methodDef.FullName.Contains(typeName + "::Startup()") || methodDef.FullName.Contains(typeName + "::Execute()"))
						{
							this.initializeMethod = methodDef;
							this.foundRtType = true;
						}
					}
				}
			}
			this.decrypter = new DNGDecrypter(this.module);
			if (this.decrypter != null)
			{
				this.decrypter.ParseStructure();
			}
		}

		// Token: 0x0400000D RID: 13
		public static string NativeModulePath32 = string.Empty;

		// Token: 0x0400000E RID: 14
		private ModuleDefMD module;

		// Token: 0x0400000F RID: 15
		public IDecrypter decrypter;

		// Token: 0x04000010 RID: 16
		private string version;

		// Token: 0x04000011 RID: 17
		private TypeDef DNGRtType;

		// Token: 0x04000012 RID: 18
		private MethodDef initializeMethod;

		// Token: 0x04000013 RID: 19
		private bool foundRtType;

		// Token: 0x02000008 RID: 8
		public class DecrypterBase : IDecrypter
		{
			// Token: 0x06000021 RID: 33 RVA: 0x00003FB8 File Offset: 0x00002FB8
			public Dictionary<uint, uint> GetAnonymousTokens()
			{
				return this._anonymous_tokens;
			}

			// Token: 0x06000022 RID: 34 RVA: 0x00003FE0 File Offset: 0x00002FE0
			protected DecrypterBase(ModuleDefMD module)
			{
				this.module = module;
				this.reader = module.Metadata.PEImage.CreateReader();
				this.methodInfos = new Dictionary<uint, MethodsDecrypter.DecrypterBase.methodInfo>();
				this.LocateDataStructure();
				this.MetaDataValue = this.ReadMetaDataStructure();
				bool flag = this.MetaDataValue == null;
				if (flag)
				{
					throw new Exception();
				}
			}

			// Token: 0x06000023 RID: 35 RVA: 0x00004090 File Offset: 0x00003090
			private void LocateDataStructure()
			{
				foreach (ImageSectionHeader imageSectionHeader in this.module.Metadata.PEImage.ImageSectionHeaders)
				{
					bool flag = this.DataSection != null;
					if (flag)
					{
						break;
					}
					this.DataOffset = imageSectionHeader.PointerToRawData;
					this.reader.Position = this.DataOffset;
					byte[] array = this.reader.ReadBytes((int)imageSectionHeader.SizeOfRawData);
					for (int i = 0; i < array.Length; i++)
					{
						bool flag2 = array[i] == 43 && array[i + 1] == 7 && (array[i + 2] == 115 || array[i + 2] == 32 || array[i + 2] == 40) && (array[i + 7] == 43 || array[i + 7] == 45) && array[i + 8] == 7 && (array[i + 9] == 114 || array[i + 9] == 32);
						if (flag2)
						{
							this.DataSection = imageSectionHeader;
							this.DataOffset += (uint)(i + 25);
							break;
						}
					}
				}
			}

			// Token: 0x06000024 RID: 36 RVA: 0x00004200 File Offset: 0x00003200
			private uint[] ReadMetaDataStructure()
			{
				ImageDataDirectory imageDataDirectory = this.module.Metadata.PEImage.ImageNTHeaders.OptionalHeader.DataDirectories[14];
				DataReader dataReader = this.module.Metadata.PEImage.CreateReader(imageDataDirectory.VirtualAddress, 72U);
				ImageCor20Header imageCor20Header = new ImageCor20Header(ref dataReader, false);
				try
				{
					this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset(imageCor20Header.Metadata.VirtualAddress);
					bool flag = Encoding.UTF8.GetString(this.reader.ReadBytes(4)) == "BSJB";
					if (flag)
					{
						this.reader.Position = this.reader.Position - 20U;
						bool flag2 = Encoding.UTF8.GetString(this.reader.ReadBytes(4)) == "BSJB";
						if (flag2)
						{
							byte[] array = new byte[12];
							array = this.reader.ReadBytes(array.Length);
							uint[] array2 = new uint[array.Length / 4];
							Buffer.BlockCopy(array, 0, array2, 0, array.Length);
							return array2;
						}
					}
				}
				catch
				{
					return null;
				}
				return null;
			}

			// Token: 0x06000025 RID: 37 RVA: 0x00004360 File Offset: 0x00003360
			public bool VerifyKeyBuffer(byte[] keybuffFull, uint encryption_dword)
			{
				Adler32 adler = new Adler32();
				adler.Update(keybuffFull);
				byte[] array = MD5.Create().ComputeHash(keybuffFull);
				long num = adler.Value >> 16;
				long num2 = adler.Value & 65535L;
				foreach (byte b in array)
				{
					num2 += (long)((ulong)b);
					num += num2;
				}
				num = (num & 65535L) + 15L;
				return encryption_dword == (uint)((num << 16) | num2);
			}

			// Token: 0x06000026 RID: 38 RVA: 0x000043F0 File Offset: 0x000033F0
			public bool IsHVMTechnologyEnabled()
			{
				return (this.DataStructure.ProtectionFeatures & MethodsDecrypter.DecrypterBase.ProtectSettings.HVMTechnology) == MethodsDecrypter.DecrypterBase.ProtectSettings.HVMTechnology;
			}

			// Token: 0x06000027 RID: 39 RVA: 0x00004414 File Offset: 0x00003414
			public bool IsEnterpriseEdition()
			{
				return this.DataStructure.Encryption_Dword > 0U;
			}

			// Token: 0x06000028 RID: 40 RVA: 0x00004434 File Offset: 0x00003434
			public bool IsCompatibilityModeEnabled()
			{
				return (this.DataStructure.ProtectionFeatures & MethodsDecrypter.DecrypterBase.ProtectSettings.CompatibilityMode) == MethodsDecrypter.DecrypterBase.ProtectSettings.CompatibilityMode;
			}

			// Token: 0x06000029 RID: 41 RVA: 0x00004460 File Offset: 0x00003460
			public bool IsApplicationMode()
			{
				return (this.DataStructure.ProtectionFeatures & MethodsDecrypter.DecrypterBase.ProtectSettings.ApplicationMode) == MethodsDecrypter.DecrypterBase.ProtectSettings.ApplicationMode;
			}

			// Token: 0x0600002A RID: 42 RVA: 0x0000448C File Offset: 0x0000348C
			protected void DecryptXor(byte[] buff, byte[] key)
			{
				for (int i = 0; i < buff.Length; i++)
				{
					int num = i;
					buff[num] ^= key[i % key.Length];
				}
			}

			// Token: 0x0600002B RID: 43 RVA: 0x000044CC File Offset: 0x000034CC
			public byte[] DecryptPrevXor(byte[] buff, byte[] key)
			{
				byte b = 0;
				for (int i = 0; i < buff.Length; i++)
				{
					byte b2 = (byte)(buff[i] ^ key[i % key.Length] ^ b);
					b = buff[i];
					buff[i] = b2;
				}
				return buff;
			}

			// Token: 0x0600002C RID: 44 RVA: 0x00004510 File Offset: 0x00003510
			public byte[] DecryptNextXor(byte[] buff, byte[] key)
			{
				byte b = buff[0];
				for (int i = 0; i < buff.Length - 1; i++)
				{
					byte b2 = (byte)(buff[i + 1] ^ key[i % key.Length] ^ b);
					b = buff[i + 1];
					buff[i + 1] = b2;
				}
				return buff;
			}

			// Token: 0x0600002D RID: 45 RVA: 0x0000455C File Offset: 0x0000355C
			public byte[] XorSelf(byte[] buff, int startoffset, int endoffset)
			{
				for (int num = endoffset - 1; num > startoffset; num--)
				{
					buff[num] ^= buff[num - 1];
				}
				buff[0] = (byte)(buff[endoffset - 1] ^ buff[0]);
				return buff;
			}

			// Token: 0x0600002E RID: 46 RVA: 0x000045A0 File Offset: 0x000035A0
			private byte[] DecryptUS(USStream us_stream, uint length, byte[] encryption_key, uint encryption_dword_1, uint encryption_dword_2)
			{
				byte[] array = encryption_key;
				int num = 0;
				byte[] array2 = new byte[us_stream.StreamLength];
				DataReader dataReader = us_stream.CreateReader();
				dataReader.Position = 0U;
				dataReader.ReadBytes(array2, 0, (int)us_stream.StreamLength);
				dataReader.Position = 0U;
				Stream stream = new MemoryStream(array2);
				BinaryWriter binaryWriter = new BinaryWriter(stream);
				while ((ulong)dataReader.Position < (ulong)(length - 1U))
				{
					dataReader.Position += 1U;
					this.TransformEncryptionKey(ref array, encryption_dword_1 ^ dataReader.Position, encryption_dword_2);
					uint num2 = dataReader.ReadCompressedUInt32();
					binaryWriter.BaseStream.Position = (long)((ulong)dataReader.Position);
					byte[] array3 = new byte[num2 - 1U];
					dataReader.ReadBytes(array3, 0, array3.Length);
					num += array3.Length;
					for (int i = 0; i < array3.Length; i++)
					{
						byte[] array4 = array3;
						int num3 = i;
						array4[num3] ^= array[i % array.Length];
					}
					binaryWriter.Write(array3);
				}
				stream.Position = 0L;
				stream.Read(array2, 0, (int)us_stream.StreamLength);
				return array2;
			}

			// Token: 0x0600002F RID: 47 RVA: 0x000046E0 File Offset: 0x000036E0
			private byte[] DecryptUSAtOffset(uint offset, uint length, byte[] encryption_key, uint encryption_dword_1, uint encryption_dword_2)
			{
				byte[] array = encryption_key;
				byte[] array2 = new byte[length];
				DataReader dataReader = this.module.Metadata.PEImage.CreateReader();
				dataReader.Position = offset;
				dataReader.ReadBytes(array2, 0, array2.Length);
				dataReader.Position = offset;
				DataReader dataReader2 = ByteArrayDataReaderFactory.CreateReader(array2);
				Stream stream = new MemoryStream(array2);
				BinaryWriter binaryWriter = new BinaryWriter(stream);
				uint num = 1U;
				while ((ulong)num < (ulong)length)
				{
					uint position = dataReader2.Position;
					uint num2 = dataReader2.ReadCompressedUInt32();
					uint position2 = dataReader2.Position;
					binaryWriter.BaseStream.Position = (long)((ulong)dataReader2.Position);
					this.TransformEncryptionKey(ref array, encryption_dword_1 ^ num, encryption_dword_2);
					if (num2 == 0U)
					{
						throw new Exception("num2 is too short");
					}
					byte[] array3 = new byte[num2 - 1U];
					dataReader2.ReadBytes(array3, 0, array3.Length);
					for (int i = 0; i < array3.Length; i++)
					{
						byte[] array4 = array3;
						int num3 = i;
						array4[num3] ^= array[i % array.Length];
					}
					dataReader2.Position += 1U;
					binaryWriter.Write(array3);
					num += num2 + position2 - position;
				}
				stream.Position = 0L;
				stream.Read(array2, 0, array2.Length);
				return array2;
			}

			// Token: 0x06000030 RID: 48 RVA: 0x00004854 File Offset: 0x00003854
			public void TransformEncryptionKey(ref byte[] main_encryption_key, uint encryption_dword_1, uint encryption_dword_2)
			{
				uint[] array = new uint[main_encryption_key.Length / 4];
				Buffer.BlockCopy(main_encryption_key, 0, array, 0, main_encryption_key.Length);
				for (int i = 0; i < array.Length; i++)
				{
					array[i] ^= encryption_dword_2;
				}
				for (int j = 0; j < array.Length; j++)
				{
					array[j] ^= encryption_dword_1;
					main_encryption_key = new byte[array.Length * 4];
					Buffer.BlockCopy(array, 0, main_encryption_key, 0, main_encryption_key.Length);
				}
			}

			// Token: 0x06000031 RID: 49 RVA: 0x000048E8 File Offset: 0x000038E8
			private void DecryptStrings(ref byte[] fileData)
			{
				byte[] encryption_key;
				if (this.DataStructure.KeyBuffOffset > 0U)
				{
					this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.KeyBuffOffset);
					encryption_key = this.reader.ReadBytes(16);
				}
				else
				{
					encryption_key = this.KeyBuff;
				}
				if (this.DataStructure.StringsOffset == 0U)
				{
					byte[] array = this.DecryptUS(this.module.USStream, this.DataStructure.EncryptedStringsSize, encryption_key, this.MetaDataValue[0], this.DataStructure.Encryption_Dword);
					Array.Copy(array, 0, fileData, (int)this.module.USStream.StartOffset, array.Length);
				}
				else
				{
					uint num = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.StringsOffset);
					byte[] array = this.DecryptUSAtOffset(num, this.DataStructure.EncryptedStringsSize, encryption_key, this.MetaDataValue[0], this.DataStructure.Encryption_Dword);
					Array.Copy(array, 0L, fileData, (long)((ulong)num), (long)array.Length);
				}
			}

			// Token: 0x06000032 RID: 50 RVA: 0x00004A14 File Offset: 0x00003A14
			private void DecryptResources(ref byte[] fileData)
			{
				this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.ResourceStructureOffset);
				int num = 0;
				while ((long)num < (long)((ulong)this.DataStructure.ResourceCount))
				{
					uint num2 = this.reader.ReadUInt32();
					uint num3 = (this.reader.ReadUInt32() ^ num2 ^ this.DataStructure.Encryption_Dword) & 2147483647U;
					Array.Copy(BitConverter.GetBytes(num3), 0L, fileData, (long)((ulong)this.module.Metadata.PEImage.ToFileOffset((RVA)num2)), 4L);
					bool flag = this.IsHVMTechnologyEnabled();
					if (flag)
					{
						uint position = this.reader.Position;
						this.reader.Position = (uint)this.module.Metadata.PEImage.ToFileOffset(num2 + (RVA)4U);
						byte[] array = this.reader.ReadBytes((int)num3);
						this.DecryptPrevXor(array, this.KeyBuff);
						Array.Copy(array, 0L, fileData, (long)((ulong)this.module.Metadata.PEImage.ToFileOffset(num2 + (RVA)4U)), (long)((ulong)num3));
						this.reader.Position = position;
					}
					num++;
				}
			}

			// Token: 0x06000033 RID: 51 RVA: 0x00004B64 File Offset: 0x00003B64
			public string ReadUserStringFromOffset(uint token)
			{
				try
				{
					uint num;
					if (this.DataStructure.StringsOffset == 0U)
					{
						if (this.module.USStream != null)
						{
							num = (uint)this.module.USStream.StartOffset;
						}
						else
						{
							return null;
						}
					}
					else
					{
						num = (uint)this.module.Metadata.PEImage.ToFileOffset((RVA)this.DataStructure.StringsOffset);
					}
					this.reader.Position = num + token - 1U;
					uint num2 = this.reader.ReadCompressedUInt32();
					if (num2 <= 1U || num2 > 1000000U)
					{
						return null;
					}
					byte[] array = new byte[num2 - 1U];
					this.reader.ReadBytes(array, 0, array.Length);
					return Encoding.Unicode.GetString(array);
				}
				catch
				{
					return null;
				}
			}

			// Token: 0x06000034 RID: 52 RVA: 0x00004BDC File Offset: 0x00003BDC
			public virtual void DecryptInternal(ref byte[] fileData)
			{
				if (this.DataStructure.EncryptedStringsSize > 0U)
				{
					this.DecryptStrings(ref fileData);
				}
				if (this.DataStructure.ResourceCount > 0U)
				{
					this.DecryptResources(ref fileData);
				}
			}

			// Token: 0x06000035 RID: 53 RVA: 0x00004C28 File Offset: 0x00003C28
			public virtual void ParseStructure()
			{
			}

			// Token: 0x06000036 RID: 54 RVA: 0x00004C2B File Offset: 0x00003C2B
			public virtual void ReadMethods()
			{
			}

			// Token: 0x06000037 RID: 55 RVA: 0x00004C30 File Offset: 0x00003C30
			public virtual uint DecryptHVMToken(uint hvmToken, int hvmCounter, MethodsDecrypter.DecrypterBase.methodInfo mi)
			{
				return 0U;
			}

			// Token: 0x06000038 RID: 56 RVA: 0x00004C44 File Offset: 0x00003C44
			public void RestoreMethods()
			{
				if (this.methodInfos.Count > 0)
				{
					Console.ForegroundColor = ConsoleColor.Yellow;
					Console.WriteLine(string.Format("- Restoring {0} methods", this.methodInfos.Count));
					foreach (TypeDef typeDef in this.module.GetTypes())
					{
						foreach (MethodDef methodDef in typeDef.Methods)
						{
							try
							{
								if (methodDef.HasBody)
								{
									if (this.RestoreMethod(methodDef))
									{
										MethodDef methodDef2 = methodDef;
										methodDef2.ImplAttributes &= ~MethodImplAttributes.NoInlining;
										int len = 10;
										string name = methodDef.Name.Replace('\n', ' ').Replace('\r', ' ');
										if (name.Length > len)
										{
											name = name.Substring(0, len);
										}
										Console.ForegroundColor = ConsoleColor.Cyan;
										Console.WriteLine("- Restored method {0} ({1:X8})\r\n  Instrs: {2}\r\n  Locals: {3}\r\n  Exceptions: {4}", new object[]
										{
											name,
											methodDef.MDToken,
											methodDef.Body.Instructions.Count,
											methodDef.Body.Variables.Count,
											methodDef.Body.ExceptionHandlers.Count
										});
									}
								}
							}
							catch
							{
							}
						}
					}
					bool flag4 = this.methodInfos.Count != 0;
					if (flag4)
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("- {0} methods weren't restored", new object[] { this.methodInfos.Count });
					}
				}
			}

			// Token: 0x06000039 RID: 57 RVA: 0x00004EC0 File Offset: 0x00003EC0
			private bool RestoreMethod(MethodDef method)
			{
				uint rid = method.Rid;
				bool flag = !this.methodInfos.ContainsKey(rid);
				bool result;
				if (flag)
				{
					result = false;
				}
				else
				{
					ParameterList parameters = method.Parameters;
					MethodsDecrypter.DecrypterBase.methodInfo mi = this.methodInfos[rid];
					MethodReader methodReader = new MethodReader(this.module, mi, parameters, this);
					methodReader.Read(method);
					methodReader.RestoreMethod(method);
					this.methodInfos.Remove(rid);
					result = true;
				}
				return result;
			}

			// Token: 0x04000014 RID: 20
			protected ModuleDefMD module;

			// Token: 0x04000015 RID: 21
			protected DataReader reader;

			// Token: 0x04000016 RID: 22
			protected readonly Dictionary<uint, MethodsDecrypter.DecrypterBase.methodInfo> methodInfos;

			// Token: 0x04000017 RID: 23
			protected Dictionary<uint, uint> proxyMethods = new Dictionary<uint, uint>();

			// Token: 0x04000018 RID: 24
			protected List<int> fakeMethods = new List<int>();

			// Token: 0x04000019 RID: 25
			protected List<int> secureMethods = new List<int>();

			// Token: 0x0400001A RID: 26
			protected Dictionary<uint, uint> _anonymous_tokens = new Dictionary<uint, uint>();

			// Token: 0x0400001B RID: 27
			protected ImageSectionHeader DataSection;

			// Token: 0x0400001C RID: 28
			protected uint DataOffset;

			// Token: 0x0400001D RID: 29
			protected MethodsDecrypter.DecrypterBase.DataStruct DataStructure;

			// Token: 0x0400001E RID: 30
			protected uint[] MetaDataValue;

			// Token: 0x0400001F RID: 31
			protected byte[] KeyBuff = new byte[]
			{
				139, 248, 59, 251, 15, 132, 191, 25, 40, 0,
				199, 69, 232, 1, 0, 0
			};

			// Token: 0x02000009 RID: 9
			protected struct DataStruct
			{
				// Token: 0x04000020 RID: 32
				public uint Encryption_Dword;

				// Token: 0x04000021 RID: 33
				public uint MethodsBufferLength;

				// Token: 0x04000022 RID: 34
				public uint MethodsDataOffset;

				// Token: 0x04000023 RID: 35
				public uint KeyBuffOffset;

				// Token: 0x04000024 RID: 36
				public uint MethodsCount;

				// Token: 0x04000025 RID: 37
				public uint StringsOffset;

				// Token: 0x04000026 RID: 38
				public uint EncryptedStringsSize;

				// Token: 0x04000027 RID: 39
				public uint LocalsAndEHOffset;

				// Token: 0x04000028 RID: 40
				public uint LEHSize;

				// Token: 0x04000029 RID: 41
				public uint ResourceStructureOffset;

				// Token: 0x0400002A RID: 42
				public uint ResourceCount;

				// Token: 0x0400002B RID: 43
				public uint ProtectionSettings;

				// Token: 0x0400002C RID: 44
				public MethodsDecrypter.DecrypterBase.ProtectSettings ProtectionFeatures;

				// Token: 0x0400002D RID: 45
				public byte[] _MethodsOffsetTable;

				// Token: 0x0400002E RID: 46
				public byte[] LEH;

				// Token: 0x0400002F RID: 47
				public byte[] _MethodsData;
			}

			// Token: 0x0200000A RID: 10
			public struct methodInfo
			{
				// Token: 0x04000030 RID: 48
				public byte DecryptorType;

				// Token: 0x04000031 RID: 49
				public uint MethodDataOffset;

				// Token: 0x04000032 RID: 50
				public MDToken MDToken;

				// Token: 0x04000033 RID: 51
				public byte[] Header;

				// Token: 0x04000034 RID: 52
				public byte[] MethodData;

				// Token: 0x04000035 RID: 53
				public List<Local> Method_Locals;

				// Token: 0x04000036 RID: 54
				public byte[] MethodEH;

				// Token: 0x04000037 RID: 55
				public uint HvmTokenTableOffset;

				// Token: 0x04000038 RID: 56
				public uint HvmTokenTableSize;

				// Token: 0x04000039 RID: 57
				public uint[] MethodHvmTokens;

				// Token: 0x0400003A RID: 58
				public MethodDef Method;
			}

			// Token: 0x0200000B RID: 11
			[Flags]
			protected enum ProtectSettings
			{
				// Token: 0x0400003C RID: 60
				Default = 512,
				// Token: 0x0400003D RID: 61
				MorePerformanceButLessSecurity = 1,
				// Token: 0x0400003E RID: 62
				HVMTechnology = 2,
				// Token: 0x0400003F RID: 63
				HVMEHTable = 32,
				// Token: 0x04000040 RID: 64
				HVMLocalVarSigTok = 64,
				// Token: 0x04000041 RID: 65
				HVMStrings = 128,
				// Token: 0x04000042 RID: 66
				HVMIllegalAction = 256,
				// Token: 0x04000043 RID: 67
				ApplicationMode = 1024,
				// Token: 0x04000044 RID: 68
				CompatibilityMode = 2048
			}
		}
	}
}
