import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

const VerAsesoria = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  // Estados
  const [asesoria, setAsesoria] = useState(null);
  const [maestro, setMaestro] = useState(null);
  const [alumnos, setAlumnos] = useState([]);
  const [registrado, setRegistrado] = useState(false);
  const [pagado, setPagado] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Configuración de la API
  const API_BASE_URL = 'http://localhost:5000';

// const imageUrl = maestro.foto 
//   ? `${API_BASE_URL}/images/${maestro.foto}`
//   : 'https://via.placeholder.com/150';
  // Efecto para actualizar estado de inscripción
  useEffect(() => {
    console.log("Estado de inscripción actualizado:", registrado, pagado);
    setRegistrado(registrado);
    setPagado(pagado);
  }, [registrado, pagado]);

  // Efecto para cargar datos de la asesoría
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        
        const response = await axios.get(`${API_BASE_URL}/api/ver_detalle_asesoria/${id}`, {
          withCredentials: true
        });
        
        if (!response.data) {
          throw new Error('No se recibieron datos de la asesoría');
        }

        const { asesoria: asesoriaData, maestro: maestroData, alumnos: alumnosData, registrado, pagado } = response.data;
        
        // Construir objeto maestro con URL de foto
        const maestroConFoto = {
          ...maestroData,
          fotoUrl: maestroData.foto 
            ? `${API_BASE_URL}/images/${maestroData.foto.replace(/^\/+/, '')}`
            : 'https://via.placeholder.com/150'
        };
        
        setAsesoria(asesoriaData);
        setMaestro(maestroConFoto);
        setAlumnos(alumnosData || []);
        setRegistrado(registrado || false);
        setPagado(pagado || false);

      } catch (err) {
        console.error("Error al cargar datos:", err);
        setError(
          err.response?.data?.error || 
          err.message || 
          'Error al cargar la asesoría'
        );
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id]);

  if (loading) {
    return (
      <div className="container mt-4 text-center">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Cargando...</span>
        </div>
        <p className="mt-2">Cargando información de la asesoría...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mt-4">
        <div className="alert alert-danger" role="alert">
          <h4>Error</h4>
          <p>{error}</p>
          <button 
            className="btn btn-secondary" 
            onClick={() => window.location.reload()}
          >
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  if (!asesoria || !maestro) {
    return (
      <div className="container mt-4">
        <div className="alert alert-warning" role="alert">
          No se encontraron datos para esta asesoría.
        </div>
      </div>
    );
  }

  return (
    <div className="container mt-4">
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <button
          className="btn btn-outline-light"
          onClick={() => navigate('/dashboard_alumno')}
        >
          &larr;
        </button>
        <span className="navbar-brand mx-auto">Detalles de la Asesoría</span>
      </nav>

      <div className="card shadow-lg">
        <div className="card-header bg-primary text-white text-center">
          <h2 className="mb-0">{asesoria.descripcion}</h2>
        </div>
        
        <div className="card-body">
          <div className="row mb-3">
            <div className="col-md-6">
              <h4>Detalles de la Asesoría</h4>
              <p><strong>Costo:</strong> ${asesoria.costo}</p>
              <p><strong>Cupo:</strong> {alumnos.length}/{asesoria.max_alumnos} alumnos</p>
              <p><strong>Temas:</strong> {asesoria.temas}</p>
            </div>
            
            <div className="col-md-6 text-center">
              <h4>Información del Maestro</h4>
              <p><strong>Nombre:</strong> {maestro?.nombre}</p>
              <p><strong>Email:</strong> {maestro?.email}</p>
              <img
                src={maestro?.fotoUrl}
                alt={`Foto de ${maestro?.nombre || 'maestro'}`}
                className="img-fluid rounded-circle mt-2"
                style={{ 
                  width: '150px', 
                  height: '150px', 
                  objectFit: 'cover',
                  border: '3px solid #f8f9fa'
                }}
                onError={(e) => {
                  e.target.onerror = null; 
                  e.target.src = 'https://via.placeholder.com/150';
                }}
              />
            </div>
          </div>
          
          <hr />
          
          <div className="mb-4">
            <h4>Alumnos Registrados</h4>
            {alumnos.length > 0 ? (
              <div className="table-responsive">
                <table className="table table-striped">
                  <thead>
                    <tr>
                      <th>Nombre</th>
                      <th>Email</th>
                      <th>Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alumnos.map((alumno) => (
                      <tr key={alumno.id}>
                        <td>{alumno.nombre}</td>
                        <td>{alumno.email}</td>
                        <td>
                          {alumno.pagado ? (
                            <span className="badge bg-success">Pagado</span>
                          ) : (
                            <span className="badge bg-warning text-dark">Pendiente</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="alert alert-info">
                No hay alumnos registrados en esta asesoría.
              </div>
            )}
          </div>

          {registrado && pagado && asesoria.meet_link ? (
            <div className="alert alert-success">
              <h5 className="alert-heading">¡Acceso a la asesoría!</h5>
              <p>Tu enlace para unirte a la sesión:</p>
              <div className="input-group mb-3">
                <input
                  type="text"
                  className="form-control"
                  value={asesoria.meet_link}
                  readOnly
                />
                <button
                  className="btn btn-success"
                  onClick={() => window.open(asesoria.meet_link, '_blank')}
                >
                  Unirse ahora
                </button>
              </div>
              <p className="mb-0"><small>Este enlace es personal e intransferible.</small></p>
            </div>
          ) : registrado ? (
            <div className="alert alert-warning">
              <h5 className="alert-heading">Registro completado</h5>
              <p>Tu lugar está reservado. Completa el pago para obtener acceso.</p>
              <button
                className="btn btn-primary"
                onClick={() => navigate(`/pago_asesoria/${asesoria.id}`)}
              >
                Proceder al pago
              </button>
            </div>
          ) : (
            <div className="d-grid gap-2">
              <button
                className="btn btn-primary btn-lg"
                onClick={() => navigate(`/pago_asesoria/${asesoria.id}`)}
              >
                Registrarse y pagar
              </button>
            </div>
          )}
        </div>
        
        <div className="card-footer text-center">
          <button
            className="btn btn-outline-secondary"
            onClick={() => navigate(-1)}
          >
            Volver atrás
          </button>
        </div>
      </div>
    </div>
  );
};

export default VerAsesoria;