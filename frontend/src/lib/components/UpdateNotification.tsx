import React, { useEffect, useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box
} from '@mui/material';

interface UpdateInfo {
  version: string;
  releaseDate?: string;
  releaseNotes?: string;
}

interface UpdateNotificationProps {
  manualUpdateInfo?: UpdateInfo | null;
  onDismissManualUpdate?: () => void;
}

export const UpdateNotification: React.FC<UpdateNotificationProps> = ({
  manualUpdateInfo,
  onDismissManualUpdate
}) => {
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);

  // Handle manual update info from Settings
  useEffect(() => {
    if (manualUpdateInfo) {
      setUpdateInfo(manualUpdateInfo);
      setUpdateAvailable(true);
    }
  }, [manualUpdateInfo]);

  const handleDismiss = () => {
    setUpdateAvailable(false);
    if (onDismissManualUpdate) {
      onDismissManualUpdate();
    }
  };

  return (
    <>
      {/* Update Available Dialog */}
      <Dialog open={updateAvailable} onClose={handleDismiss}>
        <DialogTitle>Update Available</DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            A new version of BSV Desktop is available!
          </Typography>
          {updateInfo && (
            <>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Version: {updateInfo.version}
              </Typography>
              {updateInfo.releaseNotes && (
                <Box mt={2}>
                  <Typography variant="body2" color="textSecondary">
                    Release Notes:
                  </Typography>
                  <Box
                    sx={{
                      marginTop: 1,
                      padding: 1,
                      backgroundColor: 'background.paper',
                      borderRadius: 1,
                      border: '1px solid',
                      borderColor: 'divider'
                    }}
                  >
                    <div
                      dangerouslySetInnerHTML={{
                        __html: updateInfo.releaseNotes || 'No release notes available.'
                      }}
                      style={{
                        fontSize: '0.875rem',
                        lineHeight: 1.5,
                        color: 'text.secondary'
                      }}
                    />
                  </Box>
                </Box>
              )}
            </>
          )}
          <Typography variant="body2" color="textSecondary" style={{ marginTop: 16 }}>
            Please download the latest version from the BSV Desktop releases page.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDismiss} color="primary">
            Dismiss
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};
