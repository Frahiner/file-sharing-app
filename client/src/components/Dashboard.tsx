import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import axios from 'axios';
import './Dashboard.css';

interface FileItem {
  id: number;
  filename: string;
  original_name: string;
  file_size: number;
  uploaded_at: string;
  is_shared: boolean;
}

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [files, setFiles] = useState<FileItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [shareUrl, setShareUrl] = useState<string>('');

  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000';

  useEffect(() => {
    loadFiles();
  }, []);

  const loadFiles = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_BASE_URL}/api/files`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles(response.data);
    } catch (error) {
      console.error('Error loading files:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const token = localStorage.getItem('token');
      await axios.post(`${API_BASE_URL}/api/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}`
        }
      });
      
      setSelectedFile(null);
      const fileInput = document.getElementById('file-input') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      
      loadFiles();
      alert('Archivo subido exitosamente');
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Error al subir archivo');
    } finally {
      setUploading(false);
    }
  };

  const handleDownload = async (fileId: number, filename: string) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_BASE_URL}/api/files/${fileId}/download`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });

      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Error al descargar archivo');
    }
  };

  const handleShare = async (fileId: number) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(`${API_BASE_URL}/api/files/${fileId}/share`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setShareUrl(response.data.shareUrl);
      alert('Archivo compartido. URL copiada al portapapeles');
      navigator.clipboard.writeText(response.data.shareUrl);
      loadFiles();
    } catch (error) {
      console.error('Error sharing file:', error);
      alert('Error al compartir archivo');
    }
  };

  const handleDelete = async (fileId: number) => {
    if (!window.confirm('¿Estás seguro de eliminar este archivo?')) return;
    
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`${API_BASE_URL}/api/files/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      loadFiles();
      alert('Archivo eliminado exitosamente');
    } catch (error) {
      console.error('Error deleting file:', error);
      alert('Error al eliminar archivo');
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('es-ES');
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🔒 Sistema de Compartición de Archivos Seguro</h1>
        <div className="user-info">
          <span>👤 Bienvenido, {user?.username}</span>
          <button onClick={logout} className="logout-btn">Cerrar Sesión</button>
        </div>
      </header>

      <div className="dashboard-content">
        <div className="upload-section">
          <h2>📤 Subir Archivo</h2>
          <div className="upload-form">
            <input
              id="file-input"
              type="file"
              onChange={handleFileSelect}
              className="file-input"
              accept=".jpg,.jpeg,.png,.gif,.pdf,.txt,.doc,.docx,.xls,.xlsx,.zip,.rar"
            />
            {selectedFile && (
              <div className="selected-file">
                <p><strong>Archivo seleccionado:</strong> {selectedFile.name}</p>
                <p><strong>Tamaño:</strong> {formatFileSize(selectedFile.size)}</p>
              </div>
            )}
            <button
              onClick={handleUpload}
              disabled={!selectedFile || uploading}
              className="upload-btn"
            >
              {uploading ? '⏳ Subiendo...' : '📤 Subir Archivo'}
            </button>
          </div>
        </div>

        <div className="files-section">
          <h2>📁 Mis Archivos ({files.length})</h2>
          {loading ? (
            <div className="loading">⏳ Cargando archivos...</div>
          ) : files.length === 0 ? (
            <div className="empty-state">
              📭 No hay archivos disponibles. ¡Sube tu primer archivo!
            </div>
          ) : (
            <div className="files-grid">
              {files.map(file => (
                <div key={file.id} className="file-card">
                  <div className="file-icon">📄</div>
                  <div className="file-info">
                    <h3>{file.original_name}</h3>
                    <p className="file-size">{formatFileSize(file.file_size)}</p>
                    <p className="file-date">{formatDate(file.uploaded_at)}</p>
                    {file.is_shared && <span className="shared-badge">🔗 Compartido</span>}
                  </div>
                  <div className="file-actions">
                    <button
                      onClick={() => handleDownload(file.id, file.original_name)}
                      className="action-btn download-btn"
                      title="Descargar"
                    >
                      ⬇️
                    </button>
                    <button
                      onClick={() => handleShare(file.id)}
                      className="action-btn share-btn"
                      title="Compartir"
                    >
                      🔗
                    </button>
                    <button
                      onClick={() => handleDelete(file.id)}
                      className="action-btn delete-btn"
                      title="Eliminar"
                    >
                      🗑️
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {shareUrl && (
          <div className="share-modal">
            <div className="share-content">
              <h3>🔗 Archivo Compartido</h3>
              <p>URL de compartición:</p>
              <input type="text" value={shareUrl} readOnly />
              <button onClick={() => setShareUrl('')}>Cerrar</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;