//
// System.Net.Radius.radiusauth.cs
//
// Author:
//  Cyrille Colin (colin@univ-metz.fr)
//
// Copyright (C) Cyrille COLIN, 2005
//


using System;
namespace System.Net.Radius {
	class test {
		static void Main(string[] args) {
			if(args.Length!=4){
				ShowUsage();
				return;
			}
			try {
				RadiusClient rc = new RadiusClient(args[0],args[1]);
				RadiusPacket authPacket = rc.Authenticate(args[2],args[3]);
				RadiusPacket receivedPacket = rc.SendAndReceivePacket(authPacket);
				if(receivedPacket == null) throw new Exception ("Can't contact remote radius server !");		
				switch (receivedPacket.Type) {
					case RadiusPacketType.ACCESS_ACCEPT :
						   Console.WriteLine("accepted");
						   foreach (RadiusAttribute attr in receivedPacket.Attributes) {
								Console.WriteLine(attr.Type.ToString()+ " = " + attr.Value);
						   }
					   	break;
				 	default :
							Console.WriteLine("rejected");
						break;		
				}
			} catch (Exception e) {
				Console.WriteLine("Error : "+e.Message);
			}
		}
		private static void ShowUsage() {
			Console.WriteLine("Usage : mono radiusauth.exe hostname sharedsecret username password");
		}
	}
}
