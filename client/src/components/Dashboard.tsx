import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import axios from 'axios';
import './Dashboard.css';

interface FileItem {
  id: number;
  filename: string;
  original_name: string;
  file_size: number;
  mime_type: string;
  is_shared: boolean;
  uploaded_at: string;
}

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [files, setFiles] = useState<FileItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFiles();
  }, []);

  const loadFiles = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:3000/api/files', {
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
      await axios.post('http://localhost:3000/api/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}`
        }
      });
      
      setSelectedFile(null);
      // Limpiar el input
      const fileInput = document.querySelector('.file-input') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      
      loadFiles(); // Recargar la lista
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
      const response = await axios.get(`http://localhost:3000/api/files/${fileId}/download`, {
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
      const response = await axios.post(`http://localhost:3000/api/files/${fileId}/share`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const shareUrl = response.data.shareUrl;
      
      // Copiar al portapapeles
      navigator.clipboard.writeText(shareUrl).then(() => {
        alert(`Archivo compartido! URL copiada al portapapeles:\n${shareUrl}`);
      }).catch(() => {
        alert(`Archivo compartido! URL:\n${shareUrl}`);
      });
      
      loadFiles(); // Recargar para actualizar estado de compartido
    } catch (error) {
      console.error('Error sharing file:', error);
      alert('Error al compartir archivo');
    }
  };

  const handleDelete = async (fileId: number) => {
    if (!window.confirm('¿Estás seguro de que quieres eliminar este archivo?')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      await axios.delete(`http://localhost:3000/api/files/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      alert('Archivo eliminado exitosamente');
      loadFiles(); // Recargar la lista
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
        <h1>📁 Sistema de Compartición de Archivos</h1>
        <div className="user-info">
          <span>Bienvenido, {user?.username}</span>
          <button onClick={logout} className="logout-btn">Cerrar Sesión</button>
        </div>
      </header>

      <div className="dashboard-content">
        <div className="upload-section">
          <h2>📤 Subir Archivo</h2>
          <div className="upload-form">
            <input
              type="file"
              onChange={handleFileSelect}
              className="file-input"
              accept=".jpeg,.jpg,.png,.gif,.pdf,.txt,.doc,.docx,.xls,.xlsx,.zip,.rar"
            />
            {selectedFile && (
              <div className="selected-file">
                <p><strong>Archivo seleccionado:</strong> {selectedFile.name}</p>
                <p><strong>Tamaño:</strong> {formatFileSize(selectedFile.size)}</p>
                <p><strong>Tipo:</strong> {selectedFile.type}</p>
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
          <h2>📂 Mis Archivos ({files.length})</h2>
          {loading ? (
            <div className="loading">
              <p>⏳ Cargando archivos...</p>
            </div>
          ) : files.length === 0 ? (
            <div className="no-files">
              <p>📭 No tienes archivos subidos aún</p>
              <p>Sube tu primer archivo usando el formulario de arriba</p>
            </div>
          ) : (
            <div className="files-table">
              <table>
                <thead>
                  <tr>
                    <th>📄 Nombre</th>
                    <th>📊 Tamaño</th>
                    <th>🗂️ Tipo</th>
                    <th>📅 Fecha</th>
                    <th>🔗 Estado</th>
                    <th>⚙️ Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map(file => (
                    <tr key={file.id}>
                      <td className="filename">{file.original_name}</td>
                      <td>{formatFileSize(file.file_size)}</td>
                      <td>{file.mime_type}</td>
                      <td>{formatDate(file.uploaded_at)}</td>
                      <td>
                        <span className={`status ${file.is_shared ? 'shared' : 'private'}`}>
                          {file.is_shared ? '🔗 Compartido' : '🔒 Privado'}
                        </span>
                      </td>
                      <td className="actions">
                        <button
                          onClick={() => handleDownload(file.id, file.original_name)}
                          className="action-btn download-btn"
                          title="Descargar archivo"
                        >
                          ⬇️
                        </button>
                        <button
                          onClick={() => handleShare(file.id)}
                          className="action-btn share-btn"
                          title="Compartir archivo"
                        >
                          🔗
                        </button>
                        <button
                          onClick={() => handleDelete(file.id)}
                          className="action-btn delete-btn"
                          title="Eliminar archivo"
                        >
                          🗑️
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;