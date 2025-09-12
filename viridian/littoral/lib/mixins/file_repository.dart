import 'dart:io';

import 'package:path_provider/path_provider.dart';

mixin FileRepositoryMixin {
  static late String _ext;
  static late Directory _baseDir;
  static bool _initialized = false;

  static Future<Directory> init(String extension) async {
    if (_initialized) return _baseDir;
    _ext = extension;
    _baseDir = await getApplicationCacheDirectory();
    _initialized = true;
    return _baseDir;
  }

  Future<File> createFile(String type, String name) async {
    return await File('${_baseDir.path}/$type/$name.$_ext').create(recursive: true);
  }

  Future<File> writeBytes(String type, String name, List<int> bytes) async {
    final file = await File('${_baseDir.path}/$type/$name.$_ext').create(recursive: true);
    return await file.writeAsBytes(bytes, flush: true);
  }

  Future<List<int>?> readBytes(String type, String name) async {
    final file = File('${_baseDir.path}/$type/$name.$_ext');
    if (await file.exists()) {
      return await file.readAsBytes();
    }
    return null;
  }

  Future<void> deleteFile(String type, String name) async {
    final file = File('${_baseDir.path}/$type/$name.$_ext');
    if (await file.exists()) {
      await file.delete();
    }
  }
}
