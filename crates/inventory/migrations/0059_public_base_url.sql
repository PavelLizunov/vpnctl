ALTER TABLE display_settings ADD COLUMN public_base_url TEXT;

UPDATE display_settings
   SET public_base_url = 'https://ninitux.com'
 WHERE id = 1
   AND EXISTS (SELECT 1 FROM users);
