import 'package:hive_ce/hive.dart';

import '../user_token_bloc/model.dart';


@GenerateAdapters([AdapterSpec<Token>()])
part 'hive_adapters.g.dart';
