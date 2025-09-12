import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:hive_ce_flutter/adapters.dart';
import 'package:path_provider/path_provider.dart';

import 'hive/hive_registrar.g.dart';
import 'user_token_bloc/bloc.dart';
import 'user_token_bloc/events.dart';
import 'user_token_bloc/repository.dart';
import 'user_token_bloc/view.dart';

Future<void> initializeHive() async {
  final dir = await getApplicationCacheDirectory();
  Hive
    ..init(dir.path)
    ..registerAdapters();
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await initializeHive();

  final repository = await TokenRepository.open();

  runApp(SeasideApp(repository: repository));
}

class SeasideApp extends StatelessWidget {
  final TokenRepository repository;
  const SeasideApp({super.key, required this.repository});

  @override
  Widget build(BuildContext context) {
    return RepositoryProvider.value(
      value: repository,
      child: BlocProvider(
        create: (_) => TokenBloc(repository: repository)..add(LoadTokens()),
        child: MaterialApp(
          title: 'Token Storage',
          theme: ThemeData(primarySwatch: Colors.blue),
          home: TokenListScreen(),
        ),
      ),
    );
  }
}
