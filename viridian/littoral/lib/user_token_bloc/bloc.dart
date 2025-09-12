import 'dart:async';

import 'package:bloc/bloc.dart';

import 'events.dart';
import 'repository.dart';
import 'state.dart';

class TokenBloc extends Bloc<TokenEvent, TokenState> {
  final TokenRepository repository;

  TokenBloc({required this.repository}) : super(TokenInitial()) {
    on<LoadTokens>(_onLoad);
    on<AddRawTokenEvent>(_onAdd);
    on<DeleteTokenEvent>(_onDelete);
  }

  Future<void> _onLoad(LoadTokens event, Emitter<TokenState> emit) async {
    emit(TokenLoadInProgress());
    try {
      final tokens = repository.getAllTokens();
      emit(TokenLoadSuccess(tokens));
    } catch (e) {
      emit(TokenOperationFailure(e.toString()));
    }
  }

  Future<void> _onAdd(AddRawTokenEvent event, Emitter<TokenState> emit) async {
    try {
      await repository.addRawToken(event.token);
      final tokens = await repository.getAllTokens();
      emit(TokenLoadSuccess(tokens));
    } catch (e) {
      emit(TokenOperationFailure(e.toString()));
    }
  }

  Future<void> _onDelete(DeleteTokenEvent event, Emitter<TokenState> emit) async {
    try {
      await repository.deleteToken(event.id);
      final tokens = await repository.getAllTokens();
      emit(TokenLoadSuccess(tokens));
    } catch (e) {
      emit(TokenOperationFailure(e.toString()));
    }
  }
}
