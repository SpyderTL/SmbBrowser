using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SmbBrowser
{
	public partial class BrowserForm : Form
	{
		public BrowserForm()
		{
			InitializeComponent();

			var server = new SmbServer { Name = "Cerberus", Address = new IPAddress(new byte[] { 192, 168, 1, 69 }) };

			var serverNode = new TreeNode
			{
				Text = server.Name,
				Tag = server
			};

			serverNode.Nodes.Add("Loading...");

			treeView.Nodes.Add(serverNode);

			var server2 = new SmbServer { Name = "localhost", Address = new IPAddress(new byte[] { 127, 0, 0, 1 }) };

			var serverNode2 = new TreeNode
			{
				Text = server2.Name,
				Tag = server2
			};

			serverNode2.Nodes.Add("Loading...");

			treeView.Nodes.Add(serverNode2);
		}

		private void treeView_AfterSelect(object sender, TreeViewEventArgs e)
		{
			propertyGrid.SelectedObject = e.Node.Tag;
		}

		private void treeView_AfterExpand(object sender, TreeViewEventArgs e)
		{
			treeView.Update();

			if (e.Node.Tag is SmbServer)
				Load((SmbServer)e.Node.Tag, e.Node);
			else if (e.Node.Tag is SmbFolder)
				Load((SmbFolder)e.Node.Tag, e.Node);
		}

		private void Load(SmbFolder folder, TreeNode node)
		{
			var client = folder.Client;
			var treeID = folder.TreeID;
			var userID = folder.UserID;
			var clientProcessID = folder.ClientProcessID;
			var server = folder.Server;
			var path = folder.Path;

			// Send FIND UNIQUE Command
			var filename = path + "\\*";

			var memory = new MemoryStream();
			var writer = new BinaryWriter(memory);

			writer.Write((byte)0xFF);
			writer.Write('S');
			writer.Write('M');
			writer.Write('B');

			// Command: FIND UNIQUE
			writer.Write((byte)0x83);

			// Error: None
			writer.Write((byte)0);

			// Reserved
			writer.Write((byte)0);

			// Error Code: None
			writer.Write((ushort)0);

			// Flags: Canonical Paths, Case-Insensitive
			writer.Write((byte)0x18);

			// Flags2: Long Filenames Used, Long Filenames Allowed
			//writer.Write((ushort)0x0041);
			// Flags2: Long Filenames Allowed
			writer.Write((ushort)0x0001);

			// Client Process ID (High)
			writer.Write((ushort)0);

			// Security
			writer.Write(0);
			writer.Write(0);

			// Reserved
			writer.Write((ushort)0);

			// Tree ID
			writer.Write(treeID);

			// Client Process ID
			writer.Write((ushort)100);

			// User ID
			writer.Write(userID);

			// Multiplex ID
			writer.Write((ushort)0);

			// Parameters
			var memory2 = new MemoryStream();
			var writer2 = new BinaryWriter(memory2);

			// MaxCount (256)
			writer2.Write((ushort)0x0010);

			// Search Attributes (Directory, System, Hidden)
			writer2.Write((ushort)0x0010);

			writer2.Flush();

			// WordCount
			writer.Write((byte)(memory2.Length >> 1));

			writer.Write(memory2.ToArray());

			// Data
			memory2 = new MemoryStream();
			writer2 = new BinaryWriter(memory2);

			// Buffer Format (Null-Terminated String)
			writer2.Write((byte)4);

			// Filename
			writer2.Write(Encoding.ASCII.GetBytes(filename));
			writer2.Write((byte)0);

			// Buffer Format (Variable)
			writer2.Write((byte)5);

			// Resume Key Length (0)
			writer2.Write((ushort)0);

			writer2.Flush();

			// ByteCount
			writer.Write((ushort)memory2.Length);

			writer.Write(memory2.ToArray());

			writer.Flush();


			// Write NetBIOS Packet
			writer = new BinaryWriter(client.GetStream());

			writer.Write(IPAddress.HostToNetworkOrder((int)memory.Length));

			writer.Write(memory.ToArray());

			writer.Flush();

			// Read FIND UNIQUE Response
			var reader = new BinaryReader(client.GetStream());

			var length = IPAddress.NetworkToHostOrder(reader.ReadInt32());

			var signature = Encoding.ASCII.GetChars(reader.ReadBytes(4));

			var command = reader.ReadByte();

			var error = reader.ReadByte();
			var reserved = reader.ReadByte();
			var errorCode = reader.ReadUInt16();

			var flags = reader.ReadByte();
			var flags2 = reader.ReadUInt16();

			var clientProcessIDHigh = reader.ReadUInt16();

			var security = reader.ReadUInt64();

			var reserved2 = reader.ReadUInt16();

			treeID = reader.ReadUInt16();
			clientProcessID = reader.ReadUInt16();
			userID = reader.ReadUInt16();
			var multiplexID = reader.ReadUInt16();

			var wordCount = reader.ReadByte();

			var parameters = reader.ReadBytes(wordCount * 2);

			var byteCount = reader.ReadUInt16();

			var data = reader.ReadBytes(byteCount);

			memory = new MemoryStream(parameters);
			reader = new BinaryReader(memory);

			var count = reader.ReadUInt16();

			memory = new MemoryStream(data);
			reader = new BinaryReader(memory);

			var bufferFormat = reader.ReadByte();
			var dataLength = reader.ReadUInt16();

			node.Nodes.Clear();

			for (var index = 0; index < count; index++)
			{
				var resumeKey = reader.ReadBytes(21);
				var attributes = reader.ReadByte();
				var lastWriteTime = reader.ReadUInt16();
				var lastWriteDate = reader.ReadUInt16();
				var fileSize = reader.ReadUInt32();
				var fileName = Encoding.ASCII.GetString(reader.ReadBytes(13)).Replace("\0", "");

				if ((attributes & 0x10) != 0)
				{
					var directoryNode = new TreeNode
					{
						Text = fileName.Trim(),
						Tag = new SmbFolder
						{
							Server = server,
							Client = client,
							UserID = userID,
							TreeID = treeID,
							ClientProcessID = clientProcessID,
							Path = path + "\\" + fileName.Trim(),
						}
					};

					directoryNode.Nodes.Add("Loading...");

					node.Nodes.Add(directoryNode);
				}
				else
					node.Nodes.Add(fileName.Trim());
			}
		}

		private new void Load(SmbServer server, TreeNode node)
		{
			var client = new TcpClient();

			client.Connect(new IPEndPoint(server.Address, 445));

			var dialect = "NT LM 0.12";

			// Write SMB Packet
			var memory = new MemoryStream();
			var writer = new BinaryWriter(memory);

			writer.Write((byte)0xFF);
			writer.Write('S');
			writer.Write('M');
			writer.Write('B');

			// Command: NEGOTIATE
			writer.Write((byte)0x72);

			// Error: None
			writer.Write((byte)0);

			// Reserved
			writer.Write((byte)0);

			// Error Code: None
			writer.Write((ushort)0);

			// Flags: None
			writer.Write((byte)0);

			// Flags2: Long Filenames
			writer.Write((ushort)0x0001);

			// Client Process ID (High)
			writer.Write((ushort)0);

			// Security
			writer.Write(0);
			writer.Write(0);

			// Reserved
			writer.Write((ushort)0);

			// Tree ID
			writer.Write((ushort)0);

			// Client Process ID
			writer.Write((ushort)100);

			// User ID
			writer.Write((ushort)0);

			// Multiplex ID
			writer.Write((ushort)0);

			// WordCount
			writer.Write((byte)0);

			var dialects = "NT LM 0.12";

			// ByteCount
			writer.Write((ushort)(Encoding.ASCII.GetByteCount(dialects) + 2));

			// Type: Null Terminated Character Array
			writer.Write((byte)0x02);

			writer.Write(Encoding.ASCII.GetBytes(dialects));

			writer.Write((byte)0x00);

			writer.Flush();

			// Write NetBIOS Packet
			writer = new BinaryWriter(client.GetStream());

			writer.Write(IPAddress.HostToNetworkOrder((int)memory.Length));

			writer.Write(memory.ToArray());

			writer.Flush();

			// Read NEGOTIATE Response
			var reader = new BinaryReader(client.GetStream());

			var length = IPAddress.NetworkToHostOrder(reader.ReadInt32());

			var signature = Encoding.ASCII.GetChars(reader.ReadBytes(4));

			var command = reader.ReadByte();

			var error = reader.ReadByte();
			var reserved = reader.ReadByte();
			var errorCode = reader.ReadUInt16();

			var flags = reader.ReadByte();
			var flags2 = reader.ReadUInt16();

			var clientProcessIDHigh = reader.ReadUInt16();

			var security = reader.ReadUInt64();

			var reserved2 = reader.ReadUInt16();

			var treeID = reader.ReadUInt16();
			var clientProcessID = reader.ReadUInt16();
			var userID = reader.ReadUInt16();
			var multiplexID = reader.ReadUInt16();

			var wordCount = reader.ReadByte();

			var parameters = reader.ReadBytes(wordCount * 2);

			var byteCount = reader.ReadUInt16();

			var data = reader.ReadBytes(byteCount);

			memory = new MemoryStream(parameters);
			reader = new BinaryReader(memory);

			var dialectIndex = reader.ReadUInt16();
			var securityMode = reader.ReadByte();
			var maxMpxCount = reader.ReadUInt16();
			var maxNumberVcs = reader.ReadUInt16();
			var maxBufferSize = reader.ReadUInt32();
			var maxRawSize = reader.ReadUInt32();
			var sessionKey = reader.ReadUInt32();
			var capabilities = reader.ReadUInt32();
			var systemTime = reader.ReadUInt64();
			var timeZone = reader.ReadInt16();
			var challengeLength = reader.ReadByte();

			memory = new MemoryStream(data);
			reader = new BinaryReader(memory);

			var challenge = reader.ReadBytes(challengeLength);
			var domainName = Encoding.Unicode.GetString(reader.ReadBytes(byteCount - challengeLength));

			var serverTime = new DateTime(1601, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddTicks((long)systemTime).AddMinutes(-timeZone);
			var userSecurity = (securityMode & 1) != 0;
			var encryptPasswords = (securityMode & 2) != 0;

			// Send SETUP Command
			var domain = "";
			var accountName = "";
			var password = "";
			var nativeOS = "";
			var nativeLanMan = "";

			memory = new MemoryStream();
			writer = new BinaryWriter(memory);

			writer.Write((byte)0xFF);
			writer.Write('S');
			writer.Write('M');
			writer.Write('B');

			// Command: SETUP
			writer.Write((byte)0x73);

			// Error: None
			writer.Write((byte)0);

			// Reserved
			writer.Write((byte)0);

			// Error Code: None
			writer.Write((ushort)0);

			// Flags: None
			writer.Write((byte)0);

			// Flags2: Long Filenames
			writer.Write((ushort)0x0001);

			// Client Process ID (High)
			writer.Write((ushort)0);

			// Security
			writer.Write(0);
			writer.Write(0);

			// Reserved
			writer.Write((ushort)0);

			// Tree ID
			writer.Write((ushort)0);

			// Client Process ID
			writer.Write((ushort)100);

			// User ID
			writer.Write((ushort)0);

			// Multiplex ID
			writer.Write((ushort)0);

			// Parameters
			var memory2 = new MemoryStream();
			var writer2 = new BinaryWriter(memory2);

			// Next Command
			writer2.Write((byte)0xff);

			// Reserved
			writer2.Write((byte)0);

			// Next Parameter Offset
			writer2.Write((ushort)0);

			// Max Buffer Size
			writer2.Write((ushort)0x1000);

			// Max Request Count
			writer2.Write((ushort)0x0001);

			// Channel
			writer2.Write((ushort)0);

			// Session Key
			writer2.Write(sessionKey);

			// Oem Password Length
			writer2.Write((ushort)Encoding.ASCII.GetByteCount(password));
			//writer2.Write((ushort)0);
			//writer2.Write((ushort)16);

			// Unicode Password Length
			//writer2.Write((ushort)Encoding.Unicode.GetByteCount(password));
			writer2.Write((ushort)0);

			// Reserved
			writer2.Write(0);

			// Capabilities
			writer2.Write(0);

			writer2.Flush();

			// WordCount
			writer.Write((byte)(memory2.Length >> 1));

			writer.Write(memory2.ToArray());

			// Data
			memory2 = new MemoryStream();
			writer2 = new BinaryWriter(memory2);

			// Oem Password
			writer2.Write(Encoding.ASCII.GetBytes(password));
			//writer2.Write(new byte[] { 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE });

			// Unicode Password
			//writer2.Write(Encoding.Unicode.GetBytes(password));

			// Padding
			//if ((memory2.Position & 2) == 1)
			//	writer2.Write((byte)0);

			// Account Name
			writer2.Write(Encoding.ASCII.GetBytes(accountName));
			//writer2.Write(Encoding.Unicode.GetBytes(accountName));
			writer2.Write((byte)0);

			// Domain
			writer2.Write(Encoding.ASCII.GetBytes(domain));
			//writer2.Write(Encoding.Unicode.GetBytes(domain));
			writer2.Write((byte)0);

			// Native OS
			writer2.Write(Encoding.ASCII.GetBytes(nativeOS));
			//writer2.Write(Encoding.Unicode.GetBytes(nativeOS));
			writer2.Write((byte)0);

			// Native LanMan
			writer2.Write(Encoding.ASCII.GetBytes(nativeLanMan));
			//writer2.Write(Encoding.Unicode.GetBytes(nativeLanMan));
			writer2.Write((byte)0);

			writer2.Flush();

			// ByteCount
			writer.Write((ushort)memory2.Length);

			writer.Write(memory2.ToArray());

			writer.Flush();


			// Write NetBIOS Packet
			writer = new BinaryWriter(client.GetStream());

			writer.Write(IPAddress.HostToNetworkOrder((int)memory.Length));

			writer.Write(memory.ToArray());

			writer.Flush();


			// Read SETUP Response
			reader = new BinaryReader(client.GetStream());

			length = IPAddress.NetworkToHostOrder(reader.ReadInt32());

			signature = Encoding.ASCII.GetChars(reader.ReadBytes(4));

			command = reader.ReadByte();

			error = reader.ReadByte();
			reserved = reader.ReadByte();
			errorCode = reader.ReadUInt16();

			flags = reader.ReadByte();
			flags2 = reader.ReadUInt16();

			clientProcessIDHigh = reader.ReadUInt16();

			security = reader.ReadUInt64();

			reserved2 = reader.ReadUInt16();

			treeID = reader.ReadUInt16();
			clientProcessID = reader.ReadUInt16();
			userID = reader.ReadUInt16();
			multiplexID = reader.ReadUInt16();

			wordCount = reader.ReadByte();

			parameters = reader.ReadBytes(wordCount * 2);

			byteCount = reader.ReadUInt16();

			data = reader.ReadBytes(byteCount);

			memory = new MemoryStream(parameters);
			reader = new BinaryReader(memory);

			var nextCommand = reader.ReadByte();
			reserved = reader.ReadByte();
			var nextParameterOffset = reader.ReadUInt16();
			var action = reader.ReadUInt16();

			memory = new MemoryStream(data);
			reader = new BinaryReader(memory);

			//if ((memory.Position & 1) != 0)
			//	var padding = reader.ReadByte();

			var fields = Encoding.ASCII.GetString(reader.ReadBytes((int)(memory.Length - memory.Position))).Split('\0');

			nativeOS = fields[0];
			nativeLanMan = fields[1];
			var primaryDomain = fields[2];

			// Send TREE CONNECT Command
			password = "";
			var path = @"\\CERBERUS\VIDEO";
			var service = "?????";

			memory = new MemoryStream();
			writer = new BinaryWriter(memory);

			writer.Write((byte)0xFF);
			writer.Write('S');
			writer.Write('M');
			writer.Write('B');

			// Command: TREE CONNECT
			writer.Write((byte)0x75);

			// Error: None
			writer.Write((byte)0);

			// Reserved
			writer.Write((byte)0);

			// Error Code: None
			writer.Write((ushort)0);

			// Flags: Canonical Paths, Case-Insensitive
			writer.Write((byte)0x18);

			// Flags2: Long Filenames Used, Long Filenames Allowed
			//writer.Write((ushort)0x0041);
			// Flags2: Long Filenames Allowed
			writer.Write((ushort)0x0001);

			// Client Process ID (High)
			writer.Write((ushort)0);

			// Security
			writer.Write(0);
			writer.Write(0);

			// Reserved
			writer.Write((ushort)0);

			// Tree ID
			writer.Write((ushort)0);

			// Client Process ID
			writer.Write((ushort)100);

			// User ID
			writer.Write(userID);

			// Multiplex ID
			writer.Write((ushort)0);

			// Parameters
			memory2 = new MemoryStream();
			writer2 = new BinaryWriter(memory2);

			// Next Command
			writer2.Write((byte)0xff);

			// Reserved
			writer2.Write((byte)0);

			// Next Parameter Offset
			writer2.Write((ushort)0);

			// Flags (None)
			writer2.Write((ushort)0x0000);

			// Password Length (1)
			writer2.Write((ushort)(Encoding.ASCII.GetByteCount(password) + 1));

			writer2.Flush();

			// WordCount
			writer.Write((byte)(memory2.Length >> 1));

			writer.Write(memory2.ToArray());

			// Data
			memory2 = new MemoryStream();
			writer2 = new BinaryWriter(memory2);

			// Password
			writer2.Write(Encoding.ASCII.GetBytes(password));
			writer2.Write((byte)0);

			// Path
			writer2.Write(Encoding.ASCII.GetBytes(path));
			writer2.Write((byte)0);

			// Service
			writer2.Write(Encoding.ASCII.GetBytes(service));
			writer2.Write((byte)0);

			writer2.Flush();

			// ByteCount
			writer.Write((ushort)memory2.Length);

			writer.Write(memory2.ToArray());

			writer.Flush();


			// Write NetBIOS Packet
			writer = new BinaryWriter(client.GetStream());

			writer.Write(IPAddress.HostToNetworkOrder((int)memory.Length));

			writer.Write(memory.ToArray());

			writer.Flush();


			// Read TREE CONNECT Response
			reader = new BinaryReader(client.GetStream());

			length = IPAddress.NetworkToHostOrder(reader.ReadInt32());

			signature = Encoding.ASCII.GetChars(reader.ReadBytes(4));

			command = reader.ReadByte();

			error = reader.ReadByte();
			reserved = reader.ReadByte();
			errorCode = reader.ReadUInt16();

			flags = reader.ReadByte();
			flags2 = reader.ReadUInt16();

			clientProcessIDHigh = reader.ReadUInt16();

			security = reader.ReadUInt64();

			reserved2 = reader.ReadUInt16();

			treeID = reader.ReadUInt16();
			clientProcessID = reader.ReadUInt16();
			userID = reader.ReadUInt16();
			multiplexID = reader.ReadUInt16();

			wordCount = reader.ReadByte();

			parameters = reader.ReadBytes(wordCount * 2);

			byteCount = reader.ReadUInt16();

			data = reader.ReadBytes(byteCount);

			memory = new MemoryStream(parameters);
			reader = new BinaryReader(memory);

			nextCommand = reader.ReadByte();
			reserved = reader.ReadByte();
			nextParameterOffset = reader.ReadUInt16();
			var optionalSupport = reader.ReadUInt16();

			fields = Encoding.ASCII.GetString(data).Split((char)0);

			service = fields[0];
			var nativeFileSystem = fields[1];



			// Send FIND UNIQUE Command
			var filename = "*";

			memory = new MemoryStream();
			writer = new BinaryWriter(memory);

			writer.Write((byte)0xFF);
			writer.Write('S');
			writer.Write('M');
			writer.Write('B');

			// Command: FIND UNIQUE
			writer.Write((byte)0x83);

			// Error: None
			writer.Write((byte)0);

			// Reserved
			writer.Write((byte)0);

			// Error Code: None
			writer.Write((ushort)0);

			// Flags: Canonical Paths, Case-Insensitive
			writer.Write((byte)0x18);

			// Flags2: Long Filenames Used, Long Filenames Allowed
			//writer.Write((ushort)0x0041);
			// Flags2: Long Filenames Allowed
			writer.Write((ushort)0x0001);

			// Client Process ID (High)
			writer.Write((ushort)0);

			// Security
			writer.Write(0);
			writer.Write(0);

			// Reserved
			writer.Write((ushort)0);

			// Tree ID
			writer.Write(treeID);

			// Client Process ID
			writer.Write((ushort)100);

			// User ID
			writer.Write(userID);

			// Multiplex ID
			writer.Write((ushort)0);

			// Parameters
			memory2 = new MemoryStream();
			writer2 = new BinaryWriter(memory2);

			// MaxCount (256)
			writer2.Write((ushort)0x0010);

			// Search Attributes (Directory, System, Hidden)
			writer2.Write((ushort)0x0010);

			writer2.Flush();

			// WordCount
			writer.Write((byte)(memory2.Length >> 1));

			writer.Write(memory2.ToArray());

			// Data
			memory2 = new MemoryStream();
			writer2 = new BinaryWriter(memory2);

			// Buffer Format (Null-Terminated String)
			writer2.Write((byte)4);

			// Filename
			writer2.Write(Encoding.ASCII.GetBytes(filename));
			writer2.Write((byte)0);

			// Buffer Format (Variable)
			writer2.Write((byte)5);

			// Resume Key Length (0)
			writer2.Write((ushort)0);

			writer2.Flush();

			// ByteCount
			writer.Write((ushort)memory2.Length);

			writer.Write(memory2.ToArray());

			writer.Flush();


			// Write NetBIOS Packet
			writer = new BinaryWriter(client.GetStream());

			writer.Write(IPAddress.HostToNetworkOrder((int)memory.Length));

			writer.Write(memory.ToArray());

			writer.Flush();

			// Read FIND UNIQUE Response
			reader = new BinaryReader(client.GetStream());

			length = IPAddress.NetworkToHostOrder(reader.ReadInt32());

			signature = Encoding.ASCII.GetChars(reader.ReadBytes(4));

			command = reader.ReadByte();

			error = reader.ReadByte();
			reserved = reader.ReadByte();
			errorCode = reader.ReadUInt16();

			flags = reader.ReadByte();
			flags2 = reader.ReadUInt16();

			clientProcessIDHigh = reader.ReadUInt16();

			security = reader.ReadUInt64();

			reserved2 = reader.ReadUInt16();

			treeID = reader.ReadUInt16();
			clientProcessID = reader.ReadUInt16();
			userID = reader.ReadUInt16();
			multiplexID = reader.ReadUInt16();

			wordCount = reader.ReadByte();

			parameters = reader.ReadBytes(wordCount * 2);

			byteCount = reader.ReadUInt16();

			data = reader.ReadBytes(byteCount);

			memory = new MemoryStream(parameters);
			reader = new BinaryReader(memory);

			var count = reader.ReadUInt16();

			memory = new MemoryStream(data);
			reader = new BinaryReader(memory);

			var bufferFormat = reader.ReadByte();
			var dataLength = reader.ReadUInt16();

			node.Nodes.Clear();

			for (var index = 0; index < count; index++)
			{
				var resumeKey = reader.ReadBytes(21);
				var attributes = reader.ReadByte();
				var lastWriteTime = reader.ReadUInt16();
				var lastWriteDate = reader.ReadUInt16();
				var fileSize = reader.ReadUInt32();
				var fileName = Encoding.ASCII.GetString(reader.ReadBytes(13)).Replace("\0", "");

				if ((attributes & 0x10) != 0)
				{
					var directoryNode = new TreeNode
					{
						Text = fileName.Trim(),
						Tag = new SmbFolder
						{
							Server = server,
							Client = client,
							UserID = userID,
							TreeID = treeID,
							ClientProcessID = clientProcessID,
							Path = fileName.Trim()
						}
					};

					directoryNode.Nodes.Add("Loading...");

					node.Nodes.Add(directoryNode);
				}
				else
					node.Nodes.Add(fileName.Trim());
			}

			//client.Close();
		}

		private byte[] LmHash(string value)
		{
			// Convert to uppercase
			value = value.ToUpper();

			// Trim/Pad to 14 characters
			value = value.PadRight(14, (char)0).Substring(0, 14);

			// Split into two 7 character strings
			var values = new string[] { value.Substring(0, 7), value.Substring(7, 7) };

			// Create DES encryption keys w/ parity bit
			var keys = new byte[][] { DesCreate(values[0]), DesCreate(values[1]) };

			// Encrypt "KGS!@#$%" using both keys
			var hashes = new byte[][] { DesEncrypt("KGS!@#$%", keys[0]), DesEncrypt("KGS!@#$%", keys[1]) };

			// Combine encrypted hashes
			var result = new byte[16];

			hashes[0].CopyTo(result, 0);
			hashes[1].CopyTo(result, 8);

			return result;
		}

		private byte[] DesCreate(string value)
		{
			var algorithm = DES.Create();

			algorithm.Mode = CipherMode.ECB;
			algorithm.Padding = PaddingMode.None;

			var encryptor = algorithm.CreateEncryptor();

			//encryptor.TransformFinalBlock(

			return new byte[8];
		}

		private byte[] DesEncrypt(string value, byte[] key)
		{
			return new byte[8];
		}
	}

	internal class SmbFolder
	{
		public SmbServer Server { get; set; }
		public TcpClient Client { get; set; }
		public ushort UserID { get; set; }
		public ushort TreeID { get; set; }
		public ushort ClientProcessID { get; set; }
		public string Path { get; set; }
	}

	internal class SmbServer
	{
		public string Name { get; set; }
		public IPAddress Address { get; set; }
	}
}
