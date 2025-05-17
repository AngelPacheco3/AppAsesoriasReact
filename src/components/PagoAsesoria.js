import React, { useState, useEffect } from 'react';
import axios from 'axios';
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
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`/api/ver_asesoria/${id}`)
      .then(response => {
        setAsesoria(response.data);
        setLoading(false);
      })
      .catch(() => {
        setError('Error al cargar los datos de la asesoría.');
        setLoading(false);
      });
  }, [id]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (formData.tarjeta.length !== 16) {
      alert('El número de tarjeta debe contener 16 dígitos.');
      return;
    }

    axios.post(`/api/procesar_pago/${id}`, formData)
      .then(() => {
        alert('Pago realizado con éxito.');
        navigate('/dashboard_alumno');
      })
      .catch(() => setError('Error al procesar el pago.'));
  };

  if (loading) return <p className="text-center mt-4">Cargando datos de la asesoría...</p>;
  if (error) return <p className="text-danger text-center mt-4">{error}</p>;

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
        <div className="alert alert-warning" role="alert">
          Los pagos se realizarán al instante y no se guardará ningún dato bancario.
        </div>
        <h2 className="text-center mb-4">Pago para {asesoria?.descripcion}</h2>
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
