using System;

namespace DNGuard_Unpacker
{
	// Token: 0x02000002 RID: 2
	public sealed class Adler32
	{
		// Token: 0x17000001 RID: 1
		// (get) Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00001050
		public long Value
		{
			get
			{
				return (long)((ulong)this.checksum);
			}
		}

		// Token: 0x06000002 RID: 2 RVA: 0x00002069 File Offset: 0x00001069
		public Adler32()
		{
			this.Reset();
		}

		// Token: 0x06000003 RID: 3 RVA: 0x0000207B File Offset: 0x0000107B
		public void Reset()
		{
			this.checksum = 1U;
		}

		// Token: 0x06000004 RID: 4 RVA: 0x00002088 File Offset: 0x00001088
		public void Update(int value)
		{
			uint num = this.checksum & 65535U;
			uint num2 = this.checksum >> 16;
			num = (num + (uint)(value & 255)) % 65521U;
			num2 = (num + num2) % 65521U;
			this.checksum = (num2 << 16) + num;
		}

		// Token: 0x06000005 RID: 5 RVA: 0x000020D4 File Offset: 0x000010D4
		public void Update(byte[] buffer)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer");
			}
			this.Update(buffer, 0, buffer.Length);
		}

		// Token: 0x06000006 RID: 6 RVA: 0x00002108 File Offset: 0x00001108
		public void Update(byte[] buffer, int offset, int count)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer");
			}
			if (offset < 0)
			{
				throw new ArgumentOutOfRangeException("offset", "cannot be negative");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count", "cannot be negative");
			}
			if (offset >= buffer.Length)
			{
				throw new ArgumentOutOfRangeException("offset", "not a valid index into buffer");
			}
			if (offset + count > buffer.Length)
			{
				throw new ArgumentOutOfRangeException("count", "exceeds buffer size");
			}
			uint num = this.checksum & 65535U;
			uint num2 = this.checksum >> 16;
			while (count > 0)
			{
				int num3 = 3800;
				if (num3 > count)
				{
					num3 = count;
				}
				count -= num3;
				while (--num3 >= 0)
				{
					num += (uint)(buffer[offset++] & byte.MaxValue);
					num2 += num;
				}
				num %= 65521U;
				num2 %= 65521U;
			}
			this.checksum = (num2 << 16) | num;
		}

		// Token: 0x04000001 RID: 1
		private const uint BASE = 65521U;

		// Token: 0x04000002 RID: 2
		private uint checksum;
	}
}
