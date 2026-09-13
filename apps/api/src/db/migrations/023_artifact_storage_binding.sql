CREATE TRIGGER artifacts_storage_binding_insert
BEFORE INSERT ON artifacts
WHEN NEW.storage_name <> NEW.sha256
  OR length(NEW.sha256) <> 64
  OR NEW.sha256 GLOB '*[^a-f0-9]*'
BEGIN
  SELECT RAISE(ABORT, 'ARTIFACT_STORAGE_BINDING_INVALID');
END;

CREATE TRIGGER artifacts_storage_binding_immutable
BEFORE UPDATE OF sha256, storage_name ON artifacts
BEGIN
  SELECT RAISE(ABORT, 'ARTIFACT_STORAGE_BINDING_IMMUTABLE');
END;
