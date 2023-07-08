import torch


class FeatureExtractor(torch.nn.Module):
    def __init__(self,n_layers,dim_input,dim_hidden,dim_output):
        super(FeatureExtractor, self).__init__()
        self.n_layers = n_layers

        self.input_layer = torch.nn.Linear(dim_input,dim_hidden)
        self.fcn = torch.nn.Linear(dim_hidden,dim_hidden)
        self.output_layer = torch.nn.Linear(dim_hidden, dim_output)

        self.input_attention = torch.nn.Linear(dim_input, dim_input)
        # self.hidden_attention = torch.nn.Linear(dim_hidden, dim_hidden)
        self.activation_function = torch.nn.ReLU()
        self.input_norm = torch.nn.LayerNorm(dim_input)
        self.hidden_norm = torch.nn.LayerNorm(dim_hidden)

    def forward(self, x):
        x = self.input_norm(x)
        # att = self.input_attention(x)
        # x = torch.multiply(x, torch.softmax(att,dim=-1))
        x = self.input_layer(x)
        x = self.hidden_norm(x)
        # x = torch.nn.Dropout()(x)
        x = self.activation_function(x)

        for i in range(self.n_layers):
            # att = self.hidden_attention(x)
            x = self.fcn(x)
            # x = torch.nn.LayerNorm(x.size()[-1])(x)
            # x = torch.nn.Dropout()(x)
            x = self.activation_function(x)

        x = self.output_layer(x)
        x = self.activation_function(x)
        return x



class ContrastiveClassifier(torch.nn.Module):
    def __init__(self,n_layers_feature,dim_input_feature,dim_hidden_feature,dim_output_feature,n_layers_cls,dim_hidden_cls,dim_output_cls):
        super(ContrastiveClassifier, self).__init__()
        self.n_layers = n_layers_cls
        self.feature_extractor1 = FeatureExtractor(n_layers=n_layers_feature, dim_input=dim_input_feature, dim_hidden=dim_hidden_feature,dim_output=dim_output_feature)
        self.feature_extractor2 = FeatureExtractor(n_layers=n_layers_feature, dim_input=dim_input_feature, dim_hidden=dim_hidden_feature,dim_output=dim_output_feature)
        self.input_layer = torch.nn.Linear(2*dim_output_feature, dim_hidden_cls)
        self.hidden_layer = torch.nn.Linear(dim_hidden_cls, dim_hidden_cls)
        self.output_layer = torch.nn.Linear(dim_hidden_cls, dim_output_cls)
        self.batchnorm = torch.nn.LayerNorm(dim_hidden_cls)
        self.activation_function = torch.nn.ReLU()

    def forward(self, x1, x2):
        emb1 = self.feature_extractor1(x1)
        emb2 = self.feature_extractor2(x2)
        x = torch.cat((emb1,emb2),dim=-1)

        x = self.input_layer(x)
        x = self.batchnorm(x)
        # x = torch.nn.Dropout()(x)
        x = self.activation_function(x)

        for i in range(self.n_layers):
            x = self.hidden_layer(x)
            # x = self.batchnorm(x)
            # x = torch.nn.Dropout()(x)
            x = self.activation_function(x)

        x = self.output_layer(x)
        x = torch.sigmoid(x)

        return x