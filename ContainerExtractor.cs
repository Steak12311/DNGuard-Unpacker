using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using dnlib.DotNet;
using dnlib.PE;

namespace DNGuard_Unpacker
{
	public static class ContainerExtractor
	{
		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

		[DllImport("kernel32.dll")]
		private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll")]
		private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

		[DllImport("kernel32.dll")]
		private static extern bool CloseHandle(IntPtr hObject);

		[StructLayout(LayoutKind.Sequential)]
		private struct MEMORY_BASIC_INFORMATION
		{
			public IntPtr BaseAddress;
			public IntPtr AllocationBase;
			public uint AllocationProtect;
			public IntPtr RegionSize;
			public uint State;
			public uint Protect;
			public uint Type;
		}

		private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
		private const uint MEM_COMMIT = 0x1000;

		public static bool IsManagedAssembly(string filePath)
		{
			try
			{
				using (var pe = new PEImage(filePath))
				{
					return pe.ImageNTHeaders.OptionalHeader.DataDirectories[14].VirtualAddress != 0;
				}
			}
			catch
			{
				return false;
			}
		}

		public static string ExtractIfPacked(string exePath)
		{
			if (IsManagedAssembly(exePath))
			{
				return exePath;
			}

			Console.ForegroundColor = ConsoleColor.Yellow;
			Console.WriteLine("[*] Detected native wrapper/container. Extracting protected .NET module from memory...");
			Console.ResetColor();

			ProcessStartInfo psi = new ProcessStartInfo(exePath)
			{
				WindowStyle = ProcessWindowStyle.Hidden,
				CreateNoWindow = true,
				UseShellExecute = false
			};

			Process proc = Process.Start(psi);
			System.Threading.Thread.Sleep(2000);

			IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
			IntPtr address = IntPtr.Zero;
			MEMORY_BASIC_INFORMATION mbi;
			byte[] extractedPe = null;

			while (VirtualQueryEx(hProcess, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
			{
				if (mbi.State == MEM_COMMIT && mbi.BaseAddress == mbi.AllocationBase)
				{
					byte[] header = new byte[0x1000];
					IntPtr read;
					if (ReadProcessMemory(hProcess, mbi.BaseAddress, header, header.Length, out read))
					{
						if (header[0] == 0x4D && header[1] == 0x5A)
						{
							int e_lfanew = BitConverter.ToInt32(header, 0x3C);
							if (e_lfanew > 0 && e_lfanew < 0x800)
							{
								int magic = BitConverter.ToUInt16(header, e_lfanew + 0x18);
								if (magic == 0x10B)
								{
									uint clrRva = BitConverter.ToUInt32(header, e_lfanew + 0x18 + 208);
									short numSec = BitConverter.ToInt16(header, e_lfanew + 6);
									short sizeOpt = BitConverter.ToInt16(header, e_lfanew + 20);
									int secTable = e_lfanew + 24 + sizeOpt;

									uint maxVAddr = 0;
									for (int i = 0; i < numSec; i++)
									{
										int sOff = secTable + i * 40;
										uint vAddr = BitConverter.ToUInt32(header, sOff + 12);
										uint vSize = BitConverter.ToUInt32(header, sOff + 8);
										if (vAddr + vSize > maxVAddr) maxVAddr = vAddr + vSize;
									}

									if (maxVAddr > 0 && clrRva > 0 && clrRva < maxVAddr)
									{
										byte[] memImage = new byte[maxVAddr];
										ReadProcessMemory(hProcess, mbi.BaseAddress, memImage, memImage.Length, out read);

										try
										{
											var peImg = new PEImage(memImage, ImageLayout.Memory, true);
											var mod = ModuleDefMD.Load(peImg);
											if (mod.Find("ZYXDNGuarder", false) != null)
											{
												Console.ForegroundColor = ConsoleColor.Green;
												Console.WriteLine("[*] Found protected .NET assembly: " + mod.Assembly.FullName);
												Console.ResetColor();
												extractedPe = UnmapToFile(memImage, peImg);
												break;
											}
										}
										catch { }
									}
								}
							}
						}
					}
				}

				long next = (long)mbi.BaseAddress + (long)mbi.RegionSize;
				if (next <= (long)address || next >= 0x7FFF0000) break;
				address = (IntPtr)next;
			}

			CloseHandle(hProcess);
			try { proc.Kill(); } catch { }

			if (extractedPe != null)
			{
				string outPath = Path.Combine(Path.GetDirectoryName(exePath), Path.GetFileNameWithoutExtension(exePath) + "_extracted.exe");
				File.WriteAllBytes(outPath, extractedPe);
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("[*] Extracted assembly saved to: " + outPath);
				Console.ResetColor();
				return outPath;
			}

			throw new InvalidOperationException("Failed to extract protected .NET module from native container!");
		}

		private static byte[] UnmapToFile(byte[] memImage, PEImage peImg)
		{
			uint totalFileSize = 0;
			foreach (var sec in peImg.ImageSectionHeaders)
			{
				uint end = sec.PointerToRawData + sec.SizeOfRawData;
				if (end > totalFileSize) totalFileSize = end;
			}

			byte[] fileBytes = new byte[totalFileSize];
			uint headerSize = peImg.ImageSectionHeaders[0].PointerToRawData;
			Array.Copy(memImage, 0, fileBytes, 0, Math.Min(headerSize, (uint)memImage.Length));

			foreach (var sec in peImg.ImageSectionHeaders)
			{
				if (sec.PointerToRawData < totalFileSize && (uint)sec.VirtualAddress < memImage.Length)
				{
					int copyLen = (int)Math.Min((long)sec.SizeOfRawData, (long)(memImage.Length - (uint)sec.VirtualAddress));
					Array.Copy(memImage, (int)(uint)sec.VirtualAddress, fileBytes, (int)sec.PointerToRawData, copyLen);
				}
			}
			return fileBytes;
		}
	}
}
