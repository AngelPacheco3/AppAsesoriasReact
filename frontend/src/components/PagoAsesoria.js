import React, { useState, useEffect } from 'react';
// Asegúrate que la ruta a axiosConfig sea correcta
import axios from '../axiosConfig'; 
import { useParams, useNavigate } from 'react-router-dom';
// --- ✅ 1. IMPORTAR LOS BOTONES DE PAYPAL ---
import { PayPalButtons, usePayPalScriptReducer } from "@paypal/react-paypal-js";

const PagoAsesoria = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [asesoria, setAsesoria] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  
  // 'isPending' nos dice si el script de PayPal está cargando
  const [{ isPending }] = usePayPalScriptReducer();

  // Cargar los detalles de la asesoría (costo, descripción)
  useEffect(() => {
    // Usar la URL relativa, axiosConfig pondrá la base
    axios.get(`/api/ver_asesoria/${id}`) 
      .then(response => {
        
        // --- ✅ CORRECCIÓN: El costo está DENTRO de response.data.asesoria
        if (!response.data || !response.data.asesoria) {
            throw new Error("Respuesta de API inválida");
        }
        
        const costo = parseFloat(response.data.asesoria.costo);
        
        if (isNaN(costo) || costo <= 0) {
            setError("El costo de esta asesoría no es válido.");
            console.error("Costo inválido:", response.data.asesoria.costo);
            setLoading(false); // Detener carga si el costo es inválido
        } else {
             setAsesoria({
                ...response.data.asesoria,
                costo: costo.toFixed(2) // Asegurar 2 decimales
             });
             setLoading(false);
        }
      })
      .catch((err) => {
        console.error("Error al cargar datos de asesoría:", err);
        setError('Error al cargar los datos de la asesoría.');
        setLoading(false);
      });
  }, [id]);

  // --- ✅ 2. FUNCIÓN PARA CREAR LA ORDEN EN PAYPAL ---
  const createOrder = (data, actions) => {
    if (!asesoria || !asesoria.costo) {
        setError("No se puede crear la orden: falta el costo de la asesoría.");
        return Promise.reject(new Error("Falta el costo"));
    }
    
    console.log("Creando orden de PayPal (Sandbox) por:", asesoria.costo);
    
    return actions.order.create({
      purchase_units: [
        {
          description: asesoria.descripcion || "Asesoría ITColima", // Descripción
          amount: {
            currency_code: "MXN", // Moneda
            value: asesoria.costo, // El costo que cargamos de la API
          },
        },
      ],
      application_context: {
        shipping_preference: 'NO_SHIPPING',
      }
    });
  };

  // --- ✅ 3. FUNCIÓN CUANDO EL PAGO ES APROBADO ---
  const onApprove = (data, actions) => {
    // actions.order.capture() captura el pago en PayPal
    return actions.order.capture().then((details) => {
      
      console.log("Pago (Sandbox) capturado:", details);
      
      // El pago en PayPal fue exitoso.
      // Ahora, llamamos a NUESTRO backend para registrar este pago.
      axios.post(`/api/procesar_pago/${id}`, {
          paypal_order_id: data.orderID,
          payer_name: details.payer.name.given_name
      })
      .then(() => {
        alert('¡Pago de prueba realizado con éxito! Tu inscripción está completa.');
        navigate('/dashboard_alumno');
      })
      .catch((err) => {
        console.error("Error al registrar el pago en el backend:", err);
        setError('Tu pago de prueba fue exitoso, pero hubo un error al registrar tu inscripción. Contacta a soporte.');
      });
      
    });
  };

  // --- ✅ 4. FUNCIÓN PARA MANEJAR ERRORES DE PAYPAL ---
  const onError = (err) => {
    console.error("Error en el pago de PayPal:", err);
    setError("Ocurrió un error durante el pago de prueba. Por favor, inténtalo de nuevo.");
  };

  // ----------------- RENDERIZADO -----------------

  if (loading) return (
        <div className="container mt-4 text-center">
            <div className="spinner-border text-primary" role="status">
                <span className="visually-hidden">Cargando...</span>
            </div>
        </div>
    );

  return (
    <div className="container-fluid">
      <div style={{ height: '50px' }}></div>
      <button 
        className="btn btn-custom btn-back"
        style={{ position: 'absolute', top: '10px', left: '10px' }}
        onClick={() => navigate(-1)} // Volver atrás
      >
        ←
      </button>
      
      {/* He quitado la clase 'login-box' porque usaba un fondo blanco 
        que chocaba con el pop-up de PayPal.
        Si quieres mantener el fondo blanco, asegúrate de que el CSS 
        no interfiera con los botones de PayPal.
        Vamos a usar 'login-box' de nuevo, pero con ajustes.
      */}
      <div className="login-box mt-5">
        <h2 className="text-center mb-4">Confirmar Pago</h2>
        
        {asesoria ? (
            <div className="alert alert-info">
              <h4 className="text-center mb-1" style={{ color: '#333' }}>
                {asesoria.descripcion}
              </h4>
              <p className="text-center h3" style={{ color: '#007bff' }}>
                Total: ${asesoria.costo} MXN
              </p>
              <p className="text-center text-danger" style={{ fontWeight: 'bold' }}>
                (MODO DE PRUEBA SANDBOX)
              </p>
            </div>
        ) : (
             !error && <p className="text-center">Cargando detalles...</p> // Mostrar solo si no hay error
        )}

        {/* Mostrar error si existe */}
        {error && (
            <div className="alert alert-danger" role="alert">
              <small>{error}</small>
            </div>
        )}

        {/* --- ✅ 5. MOSTRAR EL BOTÓN DE PAYPAL --- */}
        <div style={{ zIndex: 0, position: 'relative' }}> {/* Contenedor para los botones */}
            {/* Muestra un spinner mientras carga el script de PayPal */}
            {isPending && (
            <div className="text-center">
                <div className="spinner-border text-primary" role="status">
                <span className="visually-hidden">Cargando...</span>
                </div>
            </div>
            )}
            
            {/* Muestra los botones solo si no está pendiente y hay una asesoría válida */}
            {!isPending && asesoria && !error && (
            <PayPalButtons 
                style={{ layout: "vertical" }}
                createOrder={createOrder}
                onApprove={onApprove}
                onError={onError}
                disabled={!!error || !asesoria}
            />
            )}
        </div>
        
      </div>
    </div>
  );
};

export default PagoAsesoria;
