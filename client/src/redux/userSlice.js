import { createSlice } from "@reduxjs/toolkit";

// reducers will change the functionality of the current state
const initialState = {
  currentUser: null,
  isLoading: false,
  error: false,
};
// action->data passed throgh dispatch
// payload->data inside action
export const userSlice = createSlice({
  name: "user",
  initialState,
  reducers: {
    loginStart: (state) => {
      state.isLoading = true;
    },
    loginSuccess: (state, action) => {
      state.isLoading = false;
      state.currentUser = action.payload;
    },
    loginFailed: (state) => {
      state.isLoading = false;
      state.error = true;
    },
    logout: (state) => {
      return initialState;
    },
    changeProfile: (state, action) => {
      state.currentUser.profilePicture = action.payload;
    },
    following: (state, action) => {
      if (state.currentUser.following.includes(action.payload)) {
        state.currentUser.following.splice(
          state.currentUser.following.findIndex(
            (followingId) => followingId === action.payload
          )
        );
      } else {
        state.currentUser.following.push(action.payload);
      }
    },
  },
});

export const {
  loginStart,
  loginSuccess,
  loginFailed,
  logout,
  changeProfile,
  following,
} = userSlice.actions;

export default userSlice.reducer;
