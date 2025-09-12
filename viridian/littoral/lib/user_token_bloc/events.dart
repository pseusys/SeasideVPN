import '../generated/common.pb.dart';

abstract class TokenEvent {}

class LoadTokens extends TokenEvent {}

class AddRawTokenEvent extends TokenEvent {
  final SeasideConnectionClientCertificate token;
  final List<int> publicKeyBytes;

  AddRawTokenEvent({required this.token, required this.publicKeyBytes});
}

class DeleteTokenEvent extends TokenEvent {
  final dynamic id;
  DeleteTokenEvent({required this.id});
}
