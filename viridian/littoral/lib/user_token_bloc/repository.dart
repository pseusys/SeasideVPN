import 'package:hive_ce/hive.dart';
import 'package:uuid/uuid.dart';

import '../generated/common.pb.dart';
import '../mixins/file_repository.dart';
import 'model.dart';

class TokenRepository with FileRepositoryMixin {
  static const String _TOKENS_REPOSITORY_BOX = 'tokens_hive';
  static const String _PUBLIC_KEYS_DIRECTORY_NAME = 'public_keys';
  static const String _PUBLIC_KEYS_FILE_EXTENSION = 'key';

  late final Box<Token> _box;

  TokenRepository(this._box);

  static Future<TokenRepository> open() async {
    final directory = await FileRepositoryMixin.init(_PUBLIC_KEYS_FILE_EXTENSION);
    return TokenRepository(await Hive.openBox(_TOKENS_REPOSITORY_BOX, path: directory.path));
  }

  Map<dynamic, Token> getAllTokens() {
    return Map.fromIterables(_box.keys, _box.values);
  }

  Future<void> addRawToken(SeasideConnectionClientCertificate token) async {
    final publicKeyFile = await createFile(_PUBLIC_KEYS_DIRECTORY_NAME, Uuid().v4());
    await _box.add(Token.fromProtobuf(token, publicKeyFile.path));
  }

  Future<void> deleteToken(dynamic key) async {
    final token = _box.get(key);
    if (token != null) {
      await deleteFile(_PUBLIC_KEYS_DIRECTORY_NAME, token.publicKeyFileName);
      await _box.delete(key);
    }
  }

  Future<void> close() async {
    await _box.close();
  }
}
