import 'model.dart';

abstract class TokenState {}

class TokenInitial extends TokenState {}

class TokenLoadInProgress extends TokenState {}

class TokenLoadSuccess extends TokenState {
  final Map<dynamic, Token> tokens;
  TokenLoadSuccess(this.tokens);
}

class TokenOperationFailure extends TokenState {
  final String message;
  TokenOperationFailure(this.message);
}
