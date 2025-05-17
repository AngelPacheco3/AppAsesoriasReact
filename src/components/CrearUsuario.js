import React from 'react';
import { useNavigate } from 'react-router-dom';

const CrearUsuario = () => {
  const navigate = useNavigate();

  return (
    <div className="container d-flex justify-content-center align-items-center" style={{ minHeight: '70vh' }}>
      <button className="btn btn-custom mb-3" onClick={() => navigate('/login')}>←</button>
      
      <div className="text-center bg-light p-5 rounded-lg shadow-lg" style={{ maxWidth: '500px' }}>
        <h2 className="mb-4">¿Registrarse como?</h2>
        <div className="mt-4">
          <button className="btn btn-primary btn-lg d-block mb-3" onClick={() => navigate('/registro_maestro')}>
            <i className="fas fa-chalkboard-teacher mr-2"></i> Maestro
            <p className="small mt-2">Comparte tu conocimiento y aumenta ingresos organizando asesorías.</p>
          </button>
          <button className="btn btn-secondary btn-lg d-block" onClick={() => navigate('/registro_alumno')}>
            <i className="fas fa-user-graduate mr-2"></i> Alumno
            <p className="small mt-2">Mejora tu rendimiento académico con asesorías flexibles y personalizadas.</p>
          </button>
        </div>
      </div>
    </div>
  );
};

export default CrearUsuario;
