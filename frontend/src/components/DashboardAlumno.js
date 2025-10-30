import React, { useState, useEffect } from 'react';
// Asegúrate de que esta ruta '../axiosConfig' sea correcta
import axios, { removeJWTToken } from '../axiosConfig'; 
import { useNavigate } from 'react-router-dom';

const DashboardAlumno = () => {
  const [asesorias, setAsesorias] = useState([]);
  const [error, setError] = useState('');
  const [actualizar, setActualizar] = useState(false); 
  const navigate = useNavigate();

  const cargarAsesorias = () => {
    axios.get('/api/dashboard_alumno')
      .then(response => {
        setAsesorias(Array.isArray(response.data.asesorias) ? response.data.asesorias : []);
        setError('');
      })
      .catch(err => {
        console.error("Error al cargar asesorías:", err);
        setError('Error al cargar las asesorías disponibles.');
        setAsesorias([]);
      });
  };

  useEffect(() => {
    cargarAsesorias();
  }, [actualizar]);

  // --- FUNCIÓN LOGOUT ---
  const handleLogout = async () => {
    if (window.confirm("¿Deseas cerrar sesión?")) {
      try {
        await axios.post('/api/logout', {}); // Llama al endpoint de logout del backend
        removeJWTToken(); // Elimina el token del localStorage
        console.log("Sesión cerrada correctamente.");
        setAsesorias([]); // Limpia el estado
        navigate('/login'); // Redirige al login
      } catch (err) {
        console.error("Error al cerrar sesión:", err);
        removeJWTToken(); // Asegura limpiar token incluso con error
        navigate('/login'); // Redirige al login incluso con error
      }
    }
  };
  
  // --- ✅ INICIO DE LA CORRECCIÓN ---
  // Esta función ahora navega a la ruta de alumno "/ver_asesoria/:id"
  const handleVerDetalles = (id) => {
    navigate(`/ver_asesoria/${id}`);
  };
  // --- ✅ FIN DE LA CORRECCIÓN ---

  return (
    <>
      {/* --- NAVBAR CON BOTÓN LOGOUT --- */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <span className="navbar-brand mx-auto">Asesorías Alumnos</span>
         {/* Usamos ml-auto para empujar el botón a la derecha */}
        <ul className="navbar-nav ml-auto">
          <li className="nav-item">
            {/* El botón que llama a handleLogout */}
            <button className="btn btn-light" onClick={handleLogout}>Cerrar Sesión</button>
          </li>
        </ul>
      </nav>

      <div className="container mt-4">
        <div className="card shadow-lg">
          <div className="card-body"> 
            <h2 className="text-center mb-4">Asesorías Disponibles</h2>

            {error ? (
              <p className="text-danger text-center">{error}</p>
            ) : (
              <div className="table-responsive"> 
                <table className="table table-striped table-hover table-sm"> 
                  <thead className="thead-dark">
                    <tr>
                      <th>Descripción</th>
                      <th>Costo</th>
                      <th>Máximo de Alumnos</th>
                      <th>Temas</th>
                      <th>Maestro</th>
                      <th>Acciones</th>
                    </tr>
                  </thead>
                  <tbody>
                    {asesorias.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="text-center" data-label="">No hay asesorías disponibles.</td>
                      </tr>
                    ) : (
                      asesorias.map(({ id, descripcion, costo, max_alumnos, temas, maestro }) => (
                        <tr key={id}>
                          <td data-label="Descripción">{descripcion}</td>
                          <td data-label="Costo">${costo ? costo.toFixed(2) : 'N/A'}</td>
                          <td data-label="Máximo de Alumnos">{max_alumnos}</td>
                          <td data-label="Temas">{temas}</td>
                          <td data-label="Maestro">{maestro?.nombre || 'N/A'}</td>
                          <td data-label="Acciones">
                            <button
                              className="btn btn-info btn-sm"
                              onClick={() => handleVerDetalles(id)}
                            >
                              Ver Detalles
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            <div className="text-center mt-3">
              <button className="btn btn-secondary" onClick={() => setActualizar(!actualizar)}>
                🔄 Actualizar Asesorías
              </button>
            </div>

          </div>
        </div>
      </div>
    </>
  );
};

export default DashboardAlumno;
