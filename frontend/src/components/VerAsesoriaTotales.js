import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const VerAsesoriaTotales = () => {
  const [asesorias, setAsesorias] = useState([]);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    axios.get('/api/ver_asesorias_totales')
      .then(response => setAsesorias(response.data))
      .catch(() => setError('Error al cargar las asesorías.'));
  }, []);

  const handleEditar = (id) => {
    navigate(`/editar_asesoria/${id}`);
  };

  const handleVerDetalles = (id) => {
    navigate(`/ver_asesoria/${id}`);
  };

  const handleLogout = () => {
    if (window.confirm("¿Deseas cerrar sesión?")) {
      navigate('/logout');
    }
  };

  return (
    <>
      {/* Navbar */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary">
        <button className="btn btn-outline-light" onClick={() => navigate(-1)}>←</button>
        <span className="navbar-brand">GAD</span>
        <div className="collapse navbar-collapse">
          <ul className="navbar-nav ml-auto">
            <li className="nav-item">
              <button className="btn btn-light" onClick={handleLogout}>Cerrar Sesión</button>
            </li>
          </ul>
        </div>
      </nav>

      {/* Contenido principal */}
      <div className="container mt-4">
        <h2 className="text-center">Asesorías Totales</h2>
        {error ? (
          <p className="text-danger text-center">{error}</p>
        ) : (
          <table className="table table-bordered mt-3">
            <thead>
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
                  <td colSpan="6" className="text-center">No hay asesorías disponibles.</td>
                </tr>
              ) : (
                asesorias.map(({ id, descripcion, costo, max_alumnos, temas, maestro }) => (
                  <tr key={id}>
                    <td>{descripcion}</td>
                    <td>{costo}</td>
                    <td>{max_alumnos}</td>
                    <td>{temas}</td>
                    <td>{maestro.nombre}</td>
                    <td>
                      <button className="btn btn-info" onClick={() => handleVerDetalles(id)}>Ver Detalles</button>
                      {maestro.esActual ? (
                        <button className="btn btn-warning ml-2" onClick={() => handleEditar(id)}>Editar</button>
                      ) : null}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
};

export default VerAsesoriaTotales;
