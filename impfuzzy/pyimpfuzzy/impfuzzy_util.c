#include <Python.h>
#include <fuzzy.h>
#include <unistd.h>

static PyObject *impfuzzyError;

static PyObject * fuzzy_hash_data(PyObject *self, PyObject *args){
        PyObject *Hash = NULL;
        Py_ssize_t inputsize = 0;
        char *input = NULL;
        char *hashbuff;
        int i;

        if (!PyArg_ParseTuple(args, "s#", &input, &inputsize))
                return NULL;

        hashbuff = malloc(FUZZY_MAX_RESULT);
        if (hashbuff == NULL) {
                PyErr_SetString(impfuzzyError, "Error cannot allocate buffer");
                return NULL;
        }

        i = fuzzy_hash_buf((unsigned char*)input, (uint32_t)inputsize, (char *)hashbuff);
        if (i == 0) {
                Hash = PyString_FromString(hashbuff);
                free(hashbuff);
                return Hash;
        } else {
                PyErr_SetString(impfuzzyError, "Error cannot compute hash");
                free(hashbuff);
                return NULL;
        }
}

static PyObject * hash_compare(PyObject *self, PyObject *args){
        char *Hash1 = NULL;
        char *Hash2 = NULL;
        int i;
        if (!PyArg_ParseTuple(args, "ss", &Hash1, &Hash2)) {
                return NULL;
        }
        i = fuzzy_compare(Hash1, Hash2);
        if (i >= 0) {
                return Py_BuildValue("i", i);
        } else {
                PyErr_SetString(impfuzzyError, "Error cannot compare fuzzy hash");
                return NULL;
        }
}

static PyMethodDef impfuzzyMethods[] = {
        {"hash_data", fuzzy_hash_data, METH_VARARGS, "calculate the fuzzy hashing for a strings"},
        {"compare", hash_compare, METH_VARARGS, "compare two ssdeep hashes"},
        {NULL, NULL}
};

static char doc[] = "Fuzzy hashing module";

PyMODINIT_FUNC
initimpfuzzyutil(void)
{
        PyObject* m;
        m = Py_InitModule3("impfuzzyutil", impfuzzyMethods, doc);
        impfuzzyError = PyErr_NewException("impfuzzy.Error", NULL, NULL);
        Py_INCREF(impfuzzyError);
        PyModule_AddObject(m, "error", impfuzzyError);
}
