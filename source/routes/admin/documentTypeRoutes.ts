import express from 'express';
import controller from '../../controllers/admin/documentType';

const router = express.Router();

router.post('/getDocumentTypes',controller.getDocumentTypes)

router.post('/insertUpdateDocumentTypes',controller.insertUpdateDocumentTypes)

router.post('/activeInactiveDocumentTypes',controller.activeInactiveDocumentTypes)

export = router;