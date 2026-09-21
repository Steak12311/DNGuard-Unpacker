using System;
using System.Collections.Generic;

namespace DNGuard_Unpacker
{
	// Token: 0x02000006 RID: 6
	public interface IDecrypter
	{
		// Token: 0x06000011 RID: 17
		void DecryptInternal(ref byte[] fileData);

		// Token: 0x06000012 RID: 18
		void ParseStructure();

		// Token: 0x06000013 RID: 19
		void RestoreMethods();

		// Token: 0x06000014 RID: 20
		void ReadMethods();

		// Token: 0x06000015 RID: 21
		bool IsHVMTechnologyEnabled();

		// Token: 0x06000016 RID: 22
		Dictionary<uint, uint> GetAnonymousTokens();

		// Token: 0x06000017 RID: 23
		string ReadUserStringFromOffset(uint offset);
	}
}
