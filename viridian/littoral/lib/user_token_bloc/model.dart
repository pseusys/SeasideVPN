import 'dart:io';

import 'package:hive_ce/hive.dart';

import '../generated/common.pb.dart';

class Token extends HiveObject {
  final String ipAddress;
  final int typhoonPort;
  final int portPort;
  final List<int> authToken;
  final String dnsAddress;
  late String publicKeyFileName;
  List<int>? _publicKeyCache;

  Token({
    required this.ipAddress,
    required this.typhoonPort,
    required this.portPort,
    required this.authToken,
    required this.dnsAddress,
    required this.publicKeyFileName,
  });

  Token.fromProtobuf(SeasideConnectionClientCertificate protoToken, String publicKeyFileName): ipAddress = protoToken.address, typhoonPort = protoToken.typhoon, portPort = protoToken.port, authToken = protoToken.token, dnsAddress = protoToken.dns {
    final file = File(publicKeyFileName)
      ..writeAsBytesSync(protoToken.public, flush: true);
    _publicKeyCache = protoToken.public;
    this.publicKeyFileName = file.path;
  }

  Token copyWith({
    String? ipAddress,
    int? typhoonPort,
    int? portPort,
    List<int>? authToken,
    String? dnsAddress,
    String? publicKeyFileName,
  }) {
    return Token(
      ipAddress: ipAddress ?? this.ipAddress,
      typhoonPort: typhoonPort ?? this.typhoonPort,
      portPort: portPort ?? this.portPort,
      authToken: authToken ?? this.authToken,
      dnsAddress: dnsAddress ?? this.dnsAddress,
      publicKeyFileName: publicKeyFileName ?? this.publicKeyFileName,
    );
  }

  Future<List<int>?> readPublicKeyBytes() async {
    if (_publicKeyCache != null) return _publicKeyCache;
    final file = File(publicKeyFileName);
    if (!await file.exists()) return null;
    _publicKeyCache = await file.readAsBytes();
    return _publicKeyCache;
  }
}
