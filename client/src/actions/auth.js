import axios from 'axios'
import { REGISTER_SUCCESS, REGISTER_FAIL } from '../actions/types'
import { setAlert } from './alert'

export const register = ({ name, email, password }) => async dispatch => {
    const config = {
        headers: {
            'Content-Type': 'application/json'
        }
    }

    const body = JSON.stringify({ name, email, password });

    try {
        const res = await axios.post('/api/users', body, config);

        dispatch({
            type: REGISTER_SUCCESS,
            payload: res.data
        });
    } catch (err) {
        var errors = err.response.data.errors;

        if (Array.isArray(errors)) {
            errors.forEach(error => {
                dispatch(setAlert(error.msg, 'danger'))
            });
        } else {
            dispatch(setAlert(errors[0].msg, 'danger'))
        }


        dispatch({
            type: REGISTER_FAIL
        })
    }
}