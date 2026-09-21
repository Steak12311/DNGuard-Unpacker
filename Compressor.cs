using System;
using System.Collections.Generic;
using System.IO;

namespace DNGuard_Unpacker
{
	// Token: 0x02000004 RID: 4
	public static class Compressor
	{
		// Token: 0x0600000D RID: 13 RVA: 0x00003864 File Offset: 0x00002864
		public static byte[] Decompress(byte[] buffer)
		{
			List<byte> list = new List<byte>();
			using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(buffer)))
			{
				uint num = binaryReader.ReadUInt32();
				byte b = binaryReader.ReadByte();
				List<Compressor.CompressorStruct> list2 = new List<Compressor.CompressorStruct>();
				for (int i = 0; i <= (int)b; i++)
				{
					list2.Add(new Compressor.CompressorStruct(binaryReader.ReadUInt32(), binaryReader.ReadByte()));
				}
				int num2 = (int)binaryReader.BaseStream.Position;
				byte[] array = binaryReader.ReadBytes(buffer.Length - (int)((b + 2) * 5));
				Array.Resize<byte>(ref array, array.Length + 3);
				Compressor.CompressorStruct[] array2 = Compressor.BuildCompressorTable(list2);
				int num3 = (int)((b + 2) * 5 * 8);
				int j = 0;
				while ((long)j < (long)((ulong)num))
				{
					int num4 = num3 >> 3;
					num4 -= num2;
					uint num5 = BitConverter.ToUInt32(array, num4);
					num5 >>= num3 & 7;
					int num6 = array2.Length - 1;
					while (array2[num6].C2 != -1)
					{
						Compressor.CompressorStruct compressorStruct = array2[num6];
						num6 = (((num5 & 1U) == 0U) ? compressorStruct.C2 : compressorStruct.C3);
						num5 >>= 1;
						num3++;
					}
					list.Add(array2[num6].b);
					j++;
				}
			}
			return list.ToArray();
		}

		// Token: 0x0600000E RID: 14 RVA: 0x00003A04 File Offset: 0x00002A04
		private static Compressor.CompressorStruct[] BuildCompressorTable(List<Compressor.CompressorStruct> Table)
		{
			List<Compressor.CompressorStruct> list = Table;
			if (Table.Count - 1 > 0)
			{
				for (int num = list.Count - 1; num > 0; num++)
				{
					Compressor.CompressorStruct compressorStruct = default(Compressor.CompressorStruct).Create();
					Compressor.CompressorStruct compressorStruct2 = default(Compressor.CompressorStruct).Create();
					Compressor.CompressorStruct compressorStruct3 = default(Compressor.CompressorStruct).Create();
					Compressor.CompressorStruct compressorStruct4 = default(Compressor.CompressorStruct).Create();
					compressorStruct3 = list[num];
					compressorStruct.C2 = Table.IndexOf(compressorStruct3);
					num--;
					compressorStruct4 = list[num];
					compressorStruct.C3 = Table.IndexOf(compressorStruct4);
					num--;
					compressorStruct.Count = compressorStruct3.Count + compressorStruct4.Count;
					Table.Add(compressorStruct);
					int num2 = num;
					while (num2 > -1 && list[num2].Count < compressorStruct.Count)
					{
						num2--;
					}
					int length = num - num2;
					compressorStruct2 = list[num2 + 1];
					compressorStruct3 = list[num2 + 2];
					Compressor.CompressorStruct[] array = list.ToArray();
					Array.Copy(array, list.IndexOf(compressorStruct2), array, list.IndexOf(compressorStruct3), length);
					list = new List<Compressor.CompressorStruct>(array);
					list[list.IndexOf(compressorStruct2)] = compressorStruct;
				}
			}
			return Table.ToArray();
		}

		// Token: 0x02000005 RID: 5
		private struct CompressorStruct
		{
			// Token: 0x0600000F RID: 15 RVA: 0x00003B8C File Offset: 0x00002B8C
			public Compressor.CompressorStruct Create()
			{
				Compressor.CompressorStruct result = default(Compressor.CompressorStruct);
				result.C2 = (result.C3 = -1);
				return result;
			}

			// Token: 0x06000010 RID: 16 RVA: 0x00003BBC File Offset: 0x00002BBC
			public CompressorStruct(uint Count, byte b)
			{
				this.Count = Count;
				this.b = b;
				this.C2 = (this.C3 = -1);
			}

			// Token: 0x04000009 RID: 9
			public uint Count;

			// Token: 0x0400000A RID: 10
			public readonly byte b;

			// Token: 0x0400000B RID: 11
			public int C2;

			// Token: 0x0400000C RID: 12
			public int C3;
		}
	}
}
