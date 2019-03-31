using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
		}

		private new void Load(SmbServer server, TreeNode node)
		{
			var client = new TcpClient();

			client.Connect(new IPEndPoint(server.Address, 445));

			var dialect = "NT LM 0.12";

			using (var memory = new MemoryStream())
			using (var writer = new BinaryWriter(memory, Encoding.ASCII, true))
			{
				// Signature
				writer.Write((byte)0xff);
				writer.Write('S');
				writer.Write('M');
				writer.Write('B');

				// Command: NEGOTIATE
				writer.Write((byte)0x72);

				// Status
				writer.Write(0);

				// Flags
				writer.Write((byte)0);
				writer.Write((short)1);

				// Security
				writer.Write((long)0);

				// Reserved
				writer.Write(0);

				// Tree ID
				writer.Write((short)0);

				// Process ID
				writer.Write((short)System.Diagnostics.Process.GetCurrentProcess().Id);

				// User ID
				writer.Write((ushort)0);

				// Multiplex ID
				writer.Write((short)100);

				// Parameters
				writer.Write((byte)0);

				// Buffer
				var data = Encoding.ASCII.GetBytes(dialect);

				writer.Write((short)(data.Length + 2));

				writer.Write((byte)2);

				writer.Write(data);

				writer.Write((byte)0);

				writer.Flush();

				memory.Position = 0;

				using (var writer2 = new BinaryWriter(client.GetStream(), Encoding.ASCII, true))
				{
					writer2.Write(IPAddress.HostToNetworkOrder((int)memory.Length));
					writer2.Write(memory.ToArray());

					writer2.Flush();
				}
			}

			using (var reader = new BinaryReader(client.GetStream()))
			{
				// NETBIOS Header
				var length = IPAddress.NetworkToHostOrder(reader.ReadInt32());

				// Signature
				var signature = reader.ReadBytes(4);

				// Command: NEGOTIATE
				var command = reader.ReadByte();

				// Status
				var status = reader.ReadInt32();

				// Flags
				var flags = reader.ReadByte();
				var flags2 = reader.ReadUInt16();

				// Process ID (High)
				var processIDHigh = reader.ReadUInt16();

				// Security
				var security = reader.ReadUInt64();

				// Reserved
				var reserved = reader.ReadUInt16();

				// Tree ID
				var treeID = reader.ReadUInt16();

				// Process ID
				var processID = reader.ReadUInt16();

				// User ID
				var userID = reader.ReadUInt16();

				// Multiplex ID
				var multiplexID = reader.ReadUInt16();

				// Parameters
				var parameterCount = reader.ReadByte();

				var parameters = reader.ReadBytes(parameterCount << 1);

				// Buffer
				var bufferLength = reader.ReadUInt16();

				var buffer = reader.ReadBytes(bufferLength);
			}
		}
	}

	internal class SmbServer
	{
		public string Name { get; set; }
		public IPAddress Address { get; set; }
	}
}
