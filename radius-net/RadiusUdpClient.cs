//
// System.Net.Radius.RadiusUdpClient.cs
//
// Author:
//  Cyrille Colin (colin@univ-metz.fr)
//
// Copyright (C) Cyrille COLIN, 2005
//

using System;
using System.Net;
using System.Net.Sockets;

namespace System.Net.Radius
{
    public class RadiusUdpClient : UdpClient
    {
        private int _socketTimeout = 6000; // set default to 6 s

        public RadiusUdpClient() : base() { }

        public RadiusUdpClient(string hostname, int port) : base(hostname, port) { }

        public void SetTimeout(int timeout)
        {
            this._socketTimeout = timeout;
        }

        public new byte[] Receive(ref IPEndPoint remoteEP)
        {
            base.Client.Poll(this._socketTimeout * 1000, SelectMode.SelectRead); //Mod by Zhuoming
            base.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, this._socketTimeout);
            byte[] data = null;

            int available = base.Client.Available;

            EndPoint endPoint = new IPEndPoint(IPAddress.Any, 0);
            if (available > 0)
            {
                byte[] recBuffer;
                recBuffer = new byte[available];
                var dataRead = base.Client.ReceiveFrom(recBuffer, ref endPoint);

                if (dataRead > 0)
                {
                    data = new byte[dataRead];
                    Array.Copy(recBuffer, 0, data, 0, dataRead);
                }
            }
            remoteEP = (IPEndPoint)endPoint;

            return data;
        }
    }
}

