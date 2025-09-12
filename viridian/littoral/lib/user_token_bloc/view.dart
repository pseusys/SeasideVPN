import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:littoral/generated/common.pb.dart';

import 'bloc.dart';
import 'events.dart';
import 'repository.dart';
import 'state.dart';

class TokenListScreen extends StatelessWidget {
  const TokenListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Tokens')),
      body: BlocBuilder<TokenBloc, TokenState>(
        builder: (context, state) {
          if (state is TokenLoadInProgress || state is TokenInitial) {
            return const Center(child: CircularProgressIndicator());
          } else if (state is TokenLoadSuccess) {
            final tokens = state.tokens.entries.toList();
            if (tokens.isEmpty) return const Center(child: Text('No tokens yet'));
            return ListView.builder(
              itemCount: tokens.length,
              itemBuilder: (context, index) {
                final token = tokens[index];
                return ListTile(
                  title: Text('${token.value.ipAddress} : ${token.value.typhoonPort}/${token.value.portPort}'),
                  subtitle: Text('DNS: ${token.value.dnsAddress}\nSmall: ${base64Encode(token.value.authToken)}'),
                  isThreeLine: true,
                  trailing: PopupMenuButton<String>(
                    onSelected: (value) async {
                      final bloc = context.read<TokenBloc>();
                      if (value == 'delete') {
                        bloc.add(DeleteTokenEvent(id: token.key));
                      } else if (value == 'view_pub') {
                        print(token.value.publicKeyFileName);
                        final bytes = await token.value.readPublicKeyBytes();
                        final base64 = bytes != null ? base64Encode(bytes) : 'not found';
                        if (context.mounted) {
                          showDialog<void>(
                            context: context,
                            builder: (_) => AlertDialog(
                              title: const Text('Public Key (base64)'),
                              content: SingleChildScrollView(child: SelectableText(base64)),
                              actions: [
                                TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Close')),
                              ],
                            ),
                          );
                        }
                      }
                    },
                    itemBuilder: (_) => [
                      const PopupMenuItem(value: 'view_pub', child: Text('View public key')),
                      const PopupMenuItem(value: 'delete', child: Text('Delete')),
                    ],
                  ),
                );
              },
            );
          } else if (state is TokenOperationFailure) {
            return Center(child: Text('Error: ${state.message}'));
          } else {
            return const SizedBox.shrink();
          }
        },
      ),
      floatingActionButton: FloatingActionButton(
        child: const Icon(Icons.add),
        onPressed: () async {
          final repo = RepositoryProvider.of<TokenRepository>(context);
          final result = await FilePicker.platform.pickFiles();
          if (result != null) {
            try {
              final file = await File(result.files.single.path!).readAsBytes();
              await repo.addRawToken(SeasideConnectionClientCertificate.fromBuffer(file));
              if (context.mounted) context.read<TokenBloc>().add(LoadTokens());
            } catch (e) {
              if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e')));
            } 
          }
        },
      ),
    );
  }
}
