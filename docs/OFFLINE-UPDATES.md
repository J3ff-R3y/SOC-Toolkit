# Offline update control plane

The update tooling supports environments where the Jeffrey server itself has no internet access.

```text
internet-connected staging
 -> acquire approved content
 -> build signed/hashed bundle
 -> approved transfer
 -> local verification
 -> import versioned release
 -> test
 -> explicit activation
 -> rollback if required
```

## Components

- `verify_offline_bundle.py`: validates archive structure, manifest, payload declarations, sizes/hashes and optional local signature policy.
- `import_verified_bundle.py`: imports a verified bundle into a versioned local release.
- `manage_release_activation.py`: controls source-specific activation pointers and rollback.

Automatic activation is appropriate only for explicitly supported knowledge-source classes. Models, runtime binaries and frontend libraries should use separate maintenance/review procedures.
