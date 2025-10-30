import React, { useState, useEffect } from 'react';
// Asegúrate de que esta ruta '../axiosConfig' sea correcta
import axios, { removeJWTToken } from '../axiosConfig'; 
import { useNavigate } from 'react-router-dom';

const DashboardMaestro = () => {
  const [asesorias, setAsesorias] = useState([]);
  const [error, setError] = useState('');
  const [actualizar, setActualizar] = useState(false);
  const navigate = useNavigate();

  // Función para cargar asesorías
  const cargarAsesorias = () => {
    axios.get('/api/dashboard_maestro')
      .then(response => {
        console.log("Datos actualizados recibidos:", response.data);
        setAsesorias(Array.isArray(response.data.asesorias) ? response.data.asesorias : []);
        setError(''); // Limpiar errores
      })
      .catch(err => {
        console.error("Error al cargar asesorías:", err);
        setError('Error al cargar las asesorías.');
        setAsesorias([]); // Limpiar en caso de error
      });
  };

  // Cargar asesorías al montar y al actualizar
  useEffect(() => {
    cargarAsesorias();
  }, [actualizar]);

  // Función de Logout
  const handleLogout = async () => {
    if (window.confirm("¿Deseas cerrar sesión?")) {
      try {
        await axios.post('/api/logout', {});
        removeJWTToken();
        console.log("Sesión cerrada correctamente.");
        setAsesorias([]);
        navigate('/login');
      } catch (err) {
        console.error("Error al cerrar sesión:", err);
        removeJWTToken();
        navigate('/login');
      }
    }
  };

  // Manejo de eliminación de asesorías
  const handleDelete = (id) => {
    if (window.confirm("¿Estás seguro de que quieres eliminar esta asesoría?")) {
      axios.delete(`/api/borrar_asesoria/${id}`)
        .then(() => {
          console.log(`Asesoría ${id} eliminada correctamente.`);
          setActualizar(!actualizar); // Forzar recarga de asesorías
        })
        .catch(() => alert("Error al eliminar la asesoría."));
    }
  };

  return (
    <>
      {/* Navbar */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <span className="navbar-brand mx-auto">Asesorías Maestros</span>
        {/* Botón de Logout añadido como en el dashboard de alumno */}
        <ul className="navbar-nav ml-auto">
          <li className="nav-item">
            <button className="btn btn-light" onClick={handleLogout}>Cerrar Sesión</button>
          </li>
        </ul>
      </nav>

      {/* Contenedor principal */}
      <div className="container mt-4">
        <div className="card shadow-lg">
          <div className="card-body"> {/* El CSS responsivo depende de .card-body */}
            <h2 className="text-center mb-4">Tus Asesorías</h2>

            {error ? (
              <p className="text-danger text-center">{error}</p>
            ) : (
              // --- (Sin cambios aquí) ---
              <div className="table-responsive">
                <table className="table table-striped table-hover table-sm">
                  <thead className="thead-dark">
                    <tr>
                      <th>Descripción</th>
                      <th>Costo</th>
                      <th>Máximo de Alumnos</th>
                      <th>Temas</th>
                      <th>Registrados</th>
                      <th>Total Pagado</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {asesorias.length === 0 ? (
                      <tr>
                        <td colSpan="7" className="text-center" data-label="">No has creado asesorías.</td>
                      </tr>
                    ) : (
                      asesorias.map(({ id, descripcion, costo, max_alumnos, temas, registrados, total_pagado }) => (
                        <tr key={id}>
                          <td data-label="Descripción">{descripcion}</td>
                          <td data-label="Costo">${costo ? costo.toFixed(2) : 'N/A'}</td>
                          <td data-label="Máx. Alumnos">{max_alumnos}</td>
                          <td data-label="Temas">{temas}</td>
                          <td data-label="Registrados">{registrados}</td>
                          <td data-label="Total Pagado">${total_pagado ? total_pagado.toFixed(2) : '0.00'}</td>
                          
                          {/* --- ✅ INICIO DE LA MODIFICACIÓN (Bootstrap 4) --- */}
                          <td data-label="Acciones">
                            {/* En la vista móvil (donde data-label="Acciones" está activo), 
                              el CSS que te di hace que el 'td' sea un bloque.
                              Ahora añadimos 'btn-block' para que cada botón ocupe el ancho 
                              y 'mb-2' para separarlos verticalmente.
                            */}
                            <div>
                              <button 
                                className="btn btn-info btn-sm btn-block mb-2" // Botón en bloque con margen inferior
                                onClick={() => navigate(`/ver_detalle_asesoria_maestro/${id}`)}
                              >
                                Ver Detalles
                              </button>

                              <button 
                                className="btn btn-danger btn-sm btn-block" // Botón en bloque
                                onClick={() => handleDelete(id)}
                              >
                                Eliminar
                              </button>
                            </div>
                          </td>
                          {/* --- ✅ FIN DE LA MODIFICACIÓN --- */}

                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* (Sin cambios aquí) */}
            <div className="text-center mt-3">
              <button className="btn btn-secondary" onClick={() => setActualizar(!actualizar)}>
                🔄 Actualizar Asesorías
              </button>
            </div>

            <button 
              className="btn btn-success btn-block mt-4" // btn-block (Bootstrap 4)
              onClick={() => navigate('/nueva_asesoria')}
            >
              Agregar Nueva Asesoría
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

export default DashboardMaestro;
