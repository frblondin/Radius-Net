//
// System.Net.Radius.RadiusClient.cs
//
// Author:
//  Cyrille Colin (colin@univ-metz.fr)
//
// Copyright (C) Cyrille COLIN, 2005
//
using System.Text;

namespace System.Net.Radius
{
    public class RadiusClient
    {
        private static int AUTH_RETRIES = 3;

        private static int DEFAULT_AUTH_PORT = 1812;
        private static int DEFAULT_ACCT_PORT = 1813;
        private static int DEFAULT_SOCKET_TIMEOUT = 6000;

        private string sharedSecret = String.Empty;
        private string hostName = String.Empty;
        private int authPort = DEFAULT_AUTH_PORT;
        private int acctPort = DEFAULT_ACCT_PORT;
        private int socketTimeout = DEFAULT_SOCKET_TIMEOUT;

        public RadiusClient(string hostName, string sharedSecret) :
            this(hostName, DEFAULT_AUTH_PORT, DEFAULT_ACCT_PORT, sharedSecret, DEFAULT_SOCKET_TIMEOUT)
        {
        }
        public RadiusClient(string hostName, int authPort, int acctPort, string sharedSecret) :
            this(hostName, authPort, acctPort, sharedSecret, DEFAULT_SOCKET_TIMEOUT)
        {
        }
        public RadiusClient(string hostName, int authPort, int acctPort, string sharedSecret, int sockTimeout)
        {
            this.hostName = hostName;
            this.authPort = authPort;
            this.acctPort = acctPort;
            this.sharedSecret = sharedSecret;
            this.socketTimeout = sockTimeout;
        }
        public RadiusPacket Authenticate(string username, string password)
        {
            RadiusPacket packet = new RadiusPacket(RadiusPacketType.ACCESS_REQUEST, this.sharedSecret);
            byte[] encryptedPass = Utils.encodePapPassword(Encoding.ASCII.GetBytes(password), packet.Authenticator, this.sharedSecret);
            packet.SetAttributes(RadiusAttributeType.USER_NAME, Encoding.ASCII.GetBytes(username));
            packet.SetAttributes(RadiusAttributeType.USER_PASSWORD, encryptedPass);
            return packet;
        }
        public RadiusPacket SendAndReceivePacket(RadiusPacket packet)
        {
            return SendAndReceivePacket(packet, AUTH_RETRIES);
        }
        public RadiusPacket SendAndReceivePacket(RadiusPacket packet, int retries)
        {
            IPEndPoint RemoteIpEndPoint = null;
            for (int x = 0; x < retries; x++)
            {
                var dt = DateTime.UtcNow;
                using (RadiusUdpClient udpClient = new RadiusUdpClient())
                {
                    udpClient.Connect(this.hostName, this.authPort);
                    udpClient.SetTimeout(this.socketTimeout);
                    Byte[] packetBinary = packet.GetBytes();
                    udpClient.Send(packetBinary, packetBinary.Length);
                    Byte[] receiveBytes = udpClient.Receive(ref RemoteIpEndPoint);
                    if (receiveBytes != null)
                    {
                        RadiusPacket receivedPacket = new RadiusPacket(receiveBytes, this.sharedSecret, packet.Authenticator);
                        if (VerifyPacket(packet, receivedPacket))
                            return receivedPacket;
                    }
                }
            }
            return null;
        }
        private bool VerifyPacket(RadiusPacket requestedPacket, RadiusPacket receivedPacket)
        {
            if (requestedPacket.Identifier != receivedPacket.Identifier) return false;
            if (requestedPacket.Authenticator.ToString() != Utils.makeRFC2865ResponseAuthenticator(receivedPacket.RawData, requestedPacket.Authenticator, sharedSecret).ToString()) return false;
            return true;
        }
        public int SocketTimeout
        {
            get { return this.socketTimeout; }
            set { this.socketTimeout = value; }
        }
    }

}
