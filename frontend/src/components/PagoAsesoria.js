import React, { useState, useEffect } from 'react';
// Asegúrate que la ruta a axiosConfig sea correcta
import axios from '../axiosConfig'; 
import { useParams, useNavigate } from 'react-router-dom';

const PagoAsesoria = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [asesoria, setAsesoria] = useState(null);
  const [formData, setFormData] = useState({
    nombre: '',
    tarjeta: '',
    vencimiento: '',
    cvv: '',
    celular: ''
  });
  
  // --- ❌ SE ELIMINA LA LÓGICA MANUAL DE CSRF ---
  // const [csrfToken, setCsrfToken] = useState(''); 
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  // Obtener datos de la asesoría
  useEffect(() => {
    // Usar la URL relativa, axiosConfig pondrá la base
    axios.get(`/api/ver_asesoria/${id}`)
      .then(response => {
        setAsesoria(response.data.asesoria); // Ajustado para tomar el objeto asesoria
        setLoading(false);
      })
      .catch(() => {
        setError('Error al cargar los datos de la asesoría.');
        setLoading(false);
      });
  }, [id]);

  // --- ❌ SE ELIMINA EL useEffect PARA OBTENER CSRF ---
  // (axiosConfig.js lo hará automáticamente)

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setError(''); // Limpiar error previo

    if (formData.tarjeta.length !== 16) {
      setError('El número de tarjeta debe contener 16 dígitos.');
      return;
    }
    
    if (!/^(0[1-9]|1[0-2])\/[0-9]{2}$/.test(formData.vencimiento)) {
        setError('Formato de vencimiento debe ser MM/AA.');
        return;
    }
    
    if (!/^\d{3}$/.test(formData.cvv)) {
        setError('El CVV debe contener 3 dígitos.');
        return;
    }

    // --- ✅ CORRECCIÓN: Enviar solo formData ---
    // axiosConfig.js adjuntará automáticamente el token JWT
    // y el token CSRF (en el header X-CSRFToken)
    axios.post(`/api/procesar_pago/${id}`, formData)
      .then(() => {
        alert('Pago realizado con éxito.');
        navigate('/dashboard_alumno');
      })
      .catch((err) => {
        console.error("Error al procesar el pago:", err);
        setError(err.response?.data?.error || 'Error al procesar el pago. Revisa tus datos.');
      });
  };

  if (loading) return <p className="text-center mt-4">Cargando datos de la asesoría...</p>;
  // Mantener el error en pantalla si existe
  // if (error) return <p className="text-danger text-center mt-4">{error}</p>;

  return (
    <div className="container-fluid">
      <div style={{ height: '50px' }}></div>
      <button 
        className="btn btn-custom btn-back"
        style={{ position: 'absolute', top: '10px', left: '10px' }}
        onClick={() => navigate('/dashboard_alumno')}
      >
        ←
      </button>
      
      <div className="login-box mt-5">
        <h2 className="text-center mb-4">Datos de Pago</h2>
        
        {/* Mostrar error si existe */}
        {error && (
            <div className="alert alert-danger" role="alert">
              <small>{error}</small>
            </div>
        )}

        <div className="alert alert-warning" role="alert">
          Los pagos se realizarán al instante y no se guardará ningún dato bancario.
        </div>
        
        {/* Mostrar info de la asesoría */}
        {asesoria ? (
            <h4 className="text-center mb-4" style={{ color: 'white' }}>
              Pago para: {asesoria.descripcion} (${asesoria.costo?.toFixed(2)})
            </h4>
        ) : (
             <p className="text-center">Cargando detalles...</p>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="nombre">Nombre del Propietario de la Tarjeta</label>
            <input 
              type="text"
              className="form-control"
              id="nombre"
              name="nombre"
              value={formData.nombre}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="tarjeta">Número de Tarjeta (Solo Débito)</label>
            <input 
              type="text"
              className="form-control"
              id="tarjeta"
              name="tarjeta"
              maxLength="16"
              pattern="\d{16}"
              placeholder="16 dígitos"
              value={formData.tarjeta}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="vencimiento">Fecha de Vencimiento (MM/AA)</label>
            <input 
              type="text"
              className="form-control"
              id="vencimiento"
              name="vencimiento"
              placeholder="MM/AA"
              pattern="(0[1-9]|1[0-2])\/[0-9]{2}"
              value={formData.vencimiento}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="cvv">CVV</label>
            <input 
              type="text"
              className="form-control"
              id="cvv"
              name="cvv"
              maxLength="3"
              pattern="\d{3}"
              placeholder="3 dígitos"
              value={formData.cvv}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="celular">Número de Celular</label>
            <input 
              type="text"
              className="form-control"
              id="celular"
              name="celular"
              pattern="\d{10}"
              placeholder="10 dígitos"
              value={formData.celular}
              onChange={handleChange}
              required
            />
          </div>
          <button type="submit" className="btn btn-primary btn-block">Pagar</button>
        </form>
      </div>
    </div>
  );
};

export default PagoAsesoria;
